use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::telemetry::TelemetryEvent;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueueLimits {
    pub max_events: u64,
    pub max_payload_bytes: u64,
    pub max_event_bytes: u64,
    pub max_db_bytes: u64,
    pub max_commands: u64,
}
impl Default for QueueLimits {
    fn default() -> Self {
        Self {
            max_events: 10_000,
            max_payload_bytes: 32 * 1024 * 1024,
            max_event_bytes: 256 * 1024,
            max_db_bytes: 128 * 1024 * 1024,
            max_commands: 10_000,
        }
    }
}
impl QueueLimits {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_events >= 10
                && self.max_events <= 100_000
                && self.max_event_bytes > 0
                && self.max_event_bytes <= 256 * 1024
                && self.max_payload_bytes >= self.max_event_bytes
                && self.max_payload_bytes <= 256 * 1024 * 1024
                && self.max_db_bytes >= self.max_payload_bytes + 1024 * 1024
                && self.max_db_bytes <= 1024 * 1024 * 1024
                && self.max_commands > 0
                && self.max_commands <= 100_000,
            "Invalid queue limits"
        );
        Ok(())
    }
}

pub struct EventQueue {
    conn: Connection,
    limits: QueueLimits,
}

impl EventQueue {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        Self::open_with_limits(path, QueueLimits::default())
    }

    pub fn open_with_limits(path: PathBuf, limits: QueueLimits) -> anyhow::Result<Self> {
        limits.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA busy_timeout=5000;
            PRAGMA wal_autocheckpoint=128;
            PRAGMA journal_size_limit=8388608;
            CREATE TABLE IF NOT EXISTS queue_metrics (id INTEGER PRIMARY KEY CHECK(id=1), dropped INTEGER NOT NULL);
            INSERT OR IGNORE INTO queue_metrics VALUES (1, 0);
            CREATE TABLE IF NOT EXISTS command_journal (
                id TEXT PRIMARY KEY, status TEXT NOT NULL, result TEXT
            );
            CREATE TABLE IF NOT EXISTS queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            ",
        )?;
        let has_priority = conn
            .prepare("PRAGMA table_info(queue)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|s| s == "priority");
        if !has_priority {
            conn.execute_batch("ALTER TABLE queue ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;
                UPDATE queue SET priority=1 WHERE json_valid(payload) AND (json_extract(payload, '$.type') IN ('detection','response_result') OR json_extract(payload, '$.severity') IN ('high','critical'));")?;
        }
        let page_size: u64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        let actual: u64 = conn.query_row(
            &format!("PRAGMA max_page_count={}", limits.max_db_bytes / page_size),
            [],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            actual * page_size <= limits.max_db_bytes,
            "Existing queue database exceeds configured quota"
        );
        Ok(Self { conn, limits })
    }

    pub fn claim_command(&self, id: &str) -> anyhow::Result<bool> {
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM command_journal WHERE id=?1)",
            [id],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(false);
        }
        let count: u64 = tx.query_row("SELECT COUNT(*) FROM command_journal", [], |r| r.get(0))?;
        anyhow::ensure!(
            count < self.limits.max_commands,
            "Command journal quota reached; refusing new actions"
        );
        tx.execute(
            "INSERT INTO command_journal (id, status) VALUES (?1, 'running')",
            [id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn command_result(&self, id: &str) -> anyhow::Result<Option<(String, serde_json::Value)>> {
        use rusqlite::OptionalExtension;
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT status, result FROM command_journal WHERE id=?1 AND result IS NOT NULL",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(status, raw)| Ok((status, serde_json::from_str(&raw)?)))
            .transpose()
    }

    pub fn finish_command(
        &self,
        id: &str,
        status: &str,
        result: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let raw = serde_json::to_string(result)?;
        let raw = if raw.len() > 256 * 1024 {
            serde_json::json!({"truncated":true, "original_bytes":raw.len()}).to_string()
        } else {
            raw
        };
        self.conn.execute(
            "UPDATE command_journal SET status=?2, result=?3 WHERE id=?1",
            params![id, status, raw],
        )?;
        Ok(())
    }

    pub fn enqueue(&self, event: &TelemetryEvent) -> anyhow::Result<()> {
        let payload = serde_json::to_string(event)?;
        let bytes = payload.len() as u64;
        let data_oversize = serde_json::to_vec(&event.data)?.len() > 240 * 1024;
        let priority = event.event_type == "detection"
            || event.event_type == "response_result"
            || matches!(event.severity.as_str(), "high" | "critical");
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM queue WHERE event_id=?1)",
            [&event.id],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(());
        }
        let (mut count, mut size): (u64, u64) = tx.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM queue",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let max_count = if priority {
            self.limits.max_events
        } else {
            self.limits.max_events * 9 / 10
        };
        let max_size = if priority {
            self.limits.max_payload_bytes
        } else {
            self.limits.max_payload_bytes * 9 / 10
        };
        if !data_oversize && bytes <= self.limits.max_event_bytes && priority {
            while count >= max_count || size + bytes > max_size {
                use rusqlite::OptionalExtension;
                let victim: Option<(i64,u64)> = tx.query_row("SELECT id,length(CAST(payload AS BLOB)) FROM queue WHERE priority=0 ORDER BY id LIMIT 1", [], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
                let Some((id, length)) = victim else {
                    break;
                };
                tx.execute("DELETE FROM queue WHERE id=?1", [id])?;
                tx.execute("UPDATE queue_metrics SET dropped=dropped+1 WHERE id=1", [])?;
                count -= 1;
                size -= length;
            }
        }
        if data_oversize
            || bytes > self.limits.max_event_bytes
            || count >= max_count
            || size + bytes > max_size
        {
            tx.execute("UPDATE queue_metrics SET dropped=dropped+1 WHERE id=1", [])?;
            tx.commit()?;
            anyhow::bail!("Telemetry quota reached; event dropped (see queue_dropped counter)");
        }
        tx.execute(
            "INSERT INTO queue(event_id,payload,created_at,priority) VALUES(?1,?2,?3,?4)",
            params![event.id, payload, event.ts, priority],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn dropped(&self) -> anyhow::Result<u64> {
        Ok(self
            .conn
            .query_row("SELECT dropped FROM queue_metrics WHERE id=1", [], |r| {
                r.get(0)
            })?)
    }

    pub fn peek(&self, limit: usize) -> anyhow::Result<Vec<TelemetryEvent>> {
        let mut out = Vec::new();
        let mut invalid = Vec::new();
        {
            let mut stmt = self.conn.prepare("SELECT id, CASE WHEN length(CAST(payload AS BLOB)) <= ?2 THEN payload ELSE NULL END FROM queue ORDER BY priority DESC,id ASC LIMIT ?1")?;
            let rows = stmt.query_map(
                params![limit.min(100), self.limits.max_event_bytes],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
            )?;
            let mut bytes = 0;
            for row in rows {
                let (id, raw) = row?;
                let Some(raw) = raw else {
                    invalid.push(id);
                    continue;
                };
                let event = match serde_json::from_str::<TelemetryEvent>(&raw) {
                    Ok(event) if serde_json::to_vec(&event.data)?.len() <= 240 * 1024 => event,
                    _ => {
                        invalid.push(id);
                        continue;
                    }
                };
                if bytes + raw.len() > 512 * 1024 {
                    break;
                }
                bytes += raw.len();
                out.push(event);
            }
        }
        if !invalid.is_empty() {
            let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
            for id in invalid {
                let deleted = tx.execute("DELETE FROM queue WHERE id=?1", [id])?;
                tx.execute(
                    "UPDATE queue_metrics SET dropped=dropped+?1 WHERE id=1",
                    [deleted],
                )?;
            }
            tx.commit()?;
        }
        Ok(out)
    }

    pub fn ack(&self, ids: &[String]) -> anyhow::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut stmt = self.conn.prepare("DELETE FROM queue WHERE event_id = ?1")?;
        for id in ids {
            stmt.execute(params![id])?;
        }
        Ok(())
    }

    pub fn len(&self) -> anyhow::Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM queue", [], |row| row.get(0))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn small_limits() -> QueueLimits {
        QueueLimits {
            max_events: 10,
            max_payload_bytes: 4096,
            max_event_bytes: 512,
            max_db_bytes: 2 * 1024 * 1024,
            max_commands: 1,
        }
    }
    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "spire-budget-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ))
    }
    #[test]
    fn corrupt_legacy_entries_do_not_block_valid_events() -> anyhow::Result<()> {
        let root = temp_path("corrupt");
        {
            let queue = EventQueue::open_with_limits(root.join("queue.db"), small_limits())?;
            queue.conn.execute("INSERT INTO queue(event_id,payload,created_at,priority) VALUES('invalid','not json','now',1)",[])?;
            queue.conn.execute("INSERT INTO queue(event_id,payload,created_at,priority) VALUES('oversize',?1,'now',1)",["x".repeat(1024)])?;
            let valid = TelemetryEvent::new("detection", "high", serde_json::json!({}));
            queue.enqueue(&valid)?;
            let batch = queue.peek(100)?;
            assert_eq!(batch.len(), 1);
            assert_eq!(batch[0].id, valid.id);
            assert_eq!(queue.dropped()?, 2);
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn queue_reserves_room_and_evicts_only_low_priority() -> anyhow::Result<()> {
        let root = temp_path("priority");
        {
            let queue = EventQueue::open_with_limits(root.join("queue.db"), small_limits())?;
            for _ in 0..9 {
                queue.enqueue(&TelemetryEvent::new(
                    "file_event",
                    "info",
                    serde_json::json!({}),
                ))?;
            }
            assert!(
                queue
                    .enqueue(&TelemetryEvent::new(
                        "file_event",
                        "info",
                        serde_json::json!({})
                    ))
                    .is_err()
            );
            for _ in 0..2 {
                queue.enqueue(&TelemetryEvent::new(
                    "detection",
                    "high",
                    serde_json::json!({}),
                ))?;
            }
            assert_eq!(queue.len()?, 10);
            assert_eq!(queue.dropped()?, 2);
            assert_eq!(
                queue
                    .peek(100)?
                    .iter()
                    .filter(|e| e.event_type == "detection")
                    .count(),
                2
            );
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn full_critical_queue_and_journal_refuse_new_work() -> anyhow::Result<()> {
        let root = temp_path("critical");
        {
            let queue = EventQueue::open_with_limits(root.join("queue.db"), small_limits())?;
            for _ in 0..10 {
                queue.enqueue(&TelemetryEvent::new(
                    "detection",
                    "high",
                    serde_json::json!({}),
                ))?;
            }
            assert!(
                queue
                    .enqueue(&TelemetryEvent::new(
                        "detection",
                        "high",
                        serde_json::json!({})
                    ))
                    .is_err()
            );
            assert_eq!(queue.len()?, 10);
            assert!(
                queue
                    .enqueue(&TelemetryEvent::new(
                        "detection",
                        "high",
                        serde_json::json!({"big":"x".repeat(513)})
                    ))
                    .is_err()
            );
            assert_eq!(queue.dropped()?, 2);
            assert!(queue.claim_command("first")?);
            assert!(!queue.claim_command("first")?);
            assert!(queue.claim_command("second").is_err());
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn restart_preserves_events_and_completed_commands() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "spire-queue-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&root)?;
        let path = root.join("queue.db");
        let event = TelemetryEvent::new("detection", "high", serde_json::json!({"path":"sample"}));
        {
            let queue = EventQueue::open(path.clone())?;
            queue.enqueue(&event)?;
            assert!(queue.claim_command("command-1")?);
            queue.finish_command("command-1", "acked", &serde_json::json!({"done":true}))?;
            assert!(queue.claim_command("interrupted")?);
        }
        {
            let queue = EventQueue::open(path)?;
            assert_eq!(queue.peek(100)?[0].id, event.id);
            assert!(!queue.claim_command("command-1")?);
            assert_eq!(queue.command_result("command-1")?.unwrap().0, "acked");
            assert!(!queue.claim_command("interrupted")?);
            assert!(queue.command_result("interrupted")?.is_none());
            queue.ack(&[event.id])?;
            assert_eq!(queue.len()?, 0);
        }
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
