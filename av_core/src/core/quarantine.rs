use anyhow::{Result, bail};
use chrono::Utc;
use dirs;
use rusqlite::Connection;
use std::fs::{self, OpenOptions, remove_file};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::core::models::ScanResult;

#[allow(dead_code)]
pub struct Quarantine {
    conn: Connection,
    result: ScanResult,
    id: i64,
}

impl Quarantine {
    pub fn quarantine_file(conn: &Connection, result: &ScanResult) -> Result<()> {
        let (path, malware_name) = match result {
            ScanResult::Threat { path, malware, .. } => (path.clone(), malware.name.clone()),
            ScanResult::YaraThreat {
                path,
                matching_rules,
                ..
            } => (
                path.clone(),
                format!("YARA Threat: {}", matching_rules.join(", ")),
            ),
            _ => bail!("Cannot quarantine non-threat result"),
        };

        let quarantine_dir = match std::env::var_os("SPIRE_STATE_DIR") {
            Some(path) => {
                let path = PathBuf::from(path);
                anyhow::ensure!(path.is_absolute(), "SPIRE_STATE_DIR must be absolute");
                path.join("quarantine")
            }
            None => dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("./.spire"))
                .join("spire_quarantine"),
        };
        Self::store(
            conn,
            &path,
            &malware_name,
            &quarantine_dir,
            result.fingerprint(),
        )?;

        Ok(())
    }

    pub fn init(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL, malware_name TEXT NOT NULL,
            quarantined_path TEXT NOT NULL, timestamp INTEGER NOT NULL
        );",
        )?;
        Ok(())
    }

    /// Preserve IDs from the old combined signature/quarantine DB exactly once.
    pub fn migrate_legacy(conn: &Connection, legacy_path: &std::path::Path) -> Result<()> {
        if !legacy_path.is_file() {
            return Ok(());
        }
        Self::init(conn)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS quarantine_imports(source TEXT PRIMARY KEY);",
        )?;
        let source = legacy_path.canonicalize()?.to_string_lossy().into_owned();
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM quarantine_imports WHERE source=?1)",
            [&source],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(());
        }
        let legacy =
            Connection::open_with_flags(legacy_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        if !legacy.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='quarantine' AND type='table')",
            [],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(());
        }
        let mut stmt = legacy.prepare(
            "SELECT id,original_path,malware_name,quarantined_path,timestamp FROM quarantine",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        for row in rows {
            let (id, original, name, stored, ts) = row?;
            tx.execute("INSERT INTO quarantine(id,original_path,malware_name,quarantined_path,timestamp) VALUES(?1,?2,?3,?4,?5)", rusqlite::params![id,original,name,stored,ts])?;
        }
        tx.execute("INSERT INTO quarantine_imports VALUES(?1)", [&source])?;
        tx.commit()?;
        Ok(())
    }

    fn store(
        conn: &Connection,
        path: &std::path::Path,
        malware_name: &str,
        directory: &std::path::Path,
        expected_sha256: Option<&str>,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        Self::init(conn)?;
        let metadata = fs::symlink_metadata(path)?;
        anyhow::ensure!(metadata.is_file(), "Only regular files may be quarantined");
        fs::create_dir_all(directory)?;
        anyhow::ensure!(
            !fs::symlink_metadata(directory)?.file_type().is_symlink(),
            "Quarantine must not be a symlink"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let mut bytes_used = 0u64;
        for (index, entry) in fs::read_dir(directory)?.enumerate() {
            anyhow::ensure!(index < 4096, "Quarantine object quota exceeded");
            bytes_used += entry?.metadata()?.len();
            anyhow::ensure!(
                bytes_used <= 1024 * 1024 * 1024,
                "Quarantine byte quota exceeded"
            );
        }
        anyhow::ensure!(
            bytes_used + metadata.len() <= 1024 * 1024 * 1024,
            "Quarantine byte quota exceeded"
        );
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dest = loop {
            let candidate = directory.join(format!(
                "{}-{}-{}",
                Utc::now().timestamp_nanos_opt().unwrap_or(0),
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&candidate) {
                Ok(mut output) => {
                    let copied = (|| -> Result<()> {
                        let mut input = fs::File::open(path)?;
                        let copied =
                            io::copy(&mut (&mut input).take(256 * 1024 * 1024 + 1), &mut output)?;
                        anyhow::ensure!(
                            copied <= 256 * 1024 * 1024,
                            "Quarantine file limit exceeded"
                        );
                        output.sync_all()?;
                        Ok(())
                    })();
                    if let Err(error) = copied {
                        let _ = remove_file(&candidate);
                        return Err(error);
                    }
                    break candidate;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        };
        if let Some(expected) = expected_sha256 {
            let verify = (|| -> Result<()> {
                let mut file = fs::File::open(&dest)?;
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 65536];
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                anyhow::ensure!(
                    hex::encode(hasher.finalize()) == expected,
                    "File differs from detected content; response refused"
                );
                Ok(())
            })();
            if let Err(error) = verify {
                let _ = remove_file(&dest);
                return Err(error);
            }
        }
        // Persist recovery information before removing the original. A crash may
        // leave both copies; it must never leave neither a file nor a record.
        if let Err(error) = conn.execute(
            "INSERT INTO quarantine (original_path, malware_name, quarantined_path, timestamp) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![path.to_string_lossy(), malware_name, dest.to_string_lossy(), Utc::now().timestamp()],
        ) {
            let _ = remove_file(&dest);
            return Err(error.into());
        }
        let current = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            current.is_file()
                && current.len() == metadata.len()
                && current.modified()? == metadata.modified()?,
            "Source changed during quarantine; original retained for reconciliation"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            anyhow::ensure!(
                current.dev() == metadata.dev() && current.ino() == metadata.ino(),
                "Source replaced during quarantine; original retained for reconciliation"
            );
        }
        remove_file(path)?;
        Ok(())
    }

    pub fn list_quarantined(conn: &Connection) -> Result<Vec<(i64, String, String, i64)>> {
        let mut stmt = conn.prepare(
            "SELECT id, original_path, malware_name, timestamp FROM quarantine ORDER BY timestamp DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;

        // Collect iterator of Result into Result<Vec>
        let items: Result<Vec<(i64, String, String, i64)>, rusqlite::Error> = rows.collect();
        items.map_err(|e| anyhow::anyhow!("Failed to collect quarantine items: {}", e))
    }

    pub fn restore_quarantined(conn: &Connection, id: i64) -> Result<()> {
        let (quarantined_path, original_path): (String, String) = conn.query_row(
            "SELECT quarantined_path, original_path FROM quarantine WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        // create_new refuses to overwrite a file created since quarantine.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut input = fs::File::open(&quarantined_path)?;
        let mut output = options.open(&original_path)?;
        if let Err(error) = io::copy(&mut input, &mut output).and_then(|_| output.sync_all()) {
            let _ = remove_file(&original_path);
            return Err(error.into());
        }
        remove_file(&quarantined_path)?;

        conn.execute("DELETE FROM quarantine WHERE id = ?1", [id])?;

        Ok(())
    }

    pub fn delete_quarantined(conn: &Connection, id: i64) -> Result<()> {
        let quarantined_path: String = conn.query_row(
            "SELECT quarantined_path FROM quarantine WHERE id = ?1",
            [id],
            |row| row.get(0),
        )?;

        remove_file(&quarantined_path)?;

        conn.execute("DELETE FROM quarantine WHERE id = ?1", [id])?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_migration_preserves_ids_and_does_not_resurrect_restored_records() -> Result<()> {
        let root = tempfile::tempdir()?;
        let legacy_path = root.path().join("legacy.db");
        let legacy = Connection::open(&legacy_path)?;
        Quarantine::init(&legacy)?;
        legacy.execute(
            "INSERT INTO quarantine VALUES(42,'original','fixture','stored',123)",
            [],
        )?;
        let state = Connection::open_in_memory()?;
        Quarantine::migrate_legacy(&state, &legacy_path)?;
        assert_eq!(Quarantine::list_quarantined(&state)?[0].0, 42);
        state.execute("DELETE FROM quarantine", [])?;
        Quarantine::migrate_legacy(&state, &legacy_path)?;
        assert!(Quarantine::list_quarantined(&state)?.is_empty());
        assert_eq!(Quarantine::list_quarantined(&legacy)?.len(), 1);
        Ok(())
    }
    #[test]
    fn changed_file_is_not_quarantined() -> Result<()> {
        use sha2::{Digest, Sha256};
        let root = tempfile::tempdir()?;
        let file = root.path().join("sample");
        fs::write(&file, b"new contents")?;
        let expected = hex::encode(Sha256::digest(b"original detected contents"));
        let conn = Connection::open_in_memory()?;
        assert!(
            Quarantine::store(
                &conn,
                &file,
                "test",
                &root.path().join("vault"),
                Some(&expected)
            )
            .is_err()
        );
        assert_eq!(fs::read(&file)?, b"new contents");
        assert!(Quarantine::list_quarantined(&conn)?.is_empty());
        Ok(())
    }
    #[test]
    fn same_names_are_preserved_and_restore_never_overwrites() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "spire-quarantine-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(root.join("a"))?;
        fs::create_dir_all(root.join("b"))?;
        let first = root.join("a/file");
        let second = root.join("b/file");
        fs::write(&first, b"first")?;
        fs::write(&second, b"second")?;
        let conn = Connection::open_in_memory()?;
        Quarantine::store(&conn, &first, "test", &root.join("vault"), None)?;
        Quarantine::store(&conn, &second, "test", &root.join("vault"), None)?;
        assert_eq!(Quarantine::list_quarantined(&conn)?.len(), 2);
        fs::write(&first, b"new file")?;
        assert!(Quarantine::restore_quarantined(&conn, 1).is_err());
        assert_eq!(fs::read(&first)?, b"new file");
        Quarantine::restore_quarantined(&conn, 2)?;
        assert_eq!(fs::read(&second)?, b"second");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn database_failure_keeps_original() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "spire-quarantine-failure-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        fs::create_dir_all(&root)?;
        let original = root.join("file");
        fs::write(&original, b"keep")?;
        let conn = Connection::open_in_memory()?;
        Quarantine::init(&conn)?;
        conn.execute_batch("CREATE TRIGGER deny_insert BEFORE INSERT ON quarantine BEGIN SELECT RAISE(ABORT, 'test failure'); END;")?;
        assert!(Quarantine::store(&conn, &original, "test", &root.join("vault"), None).is_err());
        assert_eq!(fs::read(&original)?, b"keep");
        assert_eq!(fs::read_dir(root.join("vault"))?.count(), 0);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
