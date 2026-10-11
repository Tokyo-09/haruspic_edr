use av_core::{
    SpireAvScanner,
    core::{config::Config as SpireConfig, db::ThreatDatabase, quarantine::Quarantine},
    types::QuarantineAction,
};
use chrono::{DateTime, FixedOffset, Utc};
use indicatif::MultiProgress;

use rusqlite::Connection;
use std::path::PathBuf;

use utils::generate_html_report;

pub mod utils;

#[allow(dead_code)]
pub struct AvEngine {
    spire_dir: PathBuf,
    db_path: PathBuf,
    yara_db_path: PathBuf,
    conn: Connection,
    state: Connection,
    limits: av_core::core::limits::ScanLimits,
}

impl AvEngine {
    pub fn new() -> anyhow::Result<Self> {
        let cfg = SpireConfig::load()?;
        let spire_dir = cfg.spire_dir();
        cfg.scan_limits.validate()?;
        let key = cfg
            .update_public_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Configure update_public_key in config.json"))?;
        let feed = match av_core::core::updates::active(&spire_dir, key)? {
            Some(feed) => feed,
            None => ThreatDatabase::install(
                cfg.update_url.as_deref().unwrap_or("http://127.0.0.1:8080"),
                &spire_dir,
                key,
            )?,
        };
        let db_path = feed.database;
        let yara_db_path = feed.yara_rules;
        let conn =
            Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let state = Connection::open(spire_dir.join("response.db"))?;
        Quarantine::init(&state)?;
        Quarantine::migrate_legacy(&state, &spire_dir.join(cfg.db_path()))?;

        Ok(AvEngine {
            spire_dir,
            db_path,
            yara_db_path,
            conn,
            state,
            limits: cfg.scan_limits,
        })
    }
    pub fn scan(
        &self,
        scan_type: av_core::types::OnDemaindScanModes,
        m: &MultiProgress,
        policy: av_core::core::response::ResponsePolicy,
    ) -> anyhow::Result<()> {
        match scan_type {
            av_core::types::OnDemaindScanModes::Fast { path, report } => {
                let results =
                    SpireAvScanner::scan_path_with_limits(&self.conn, &path, &self.limits)?;
                self.respond(&results, policy, m)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    println!(
                        "{}",
                        format!("Report generated at: {}", report_path.display())
                    );
                }
            }
            av_core::types::OnDemaindScanModes::Full {
                rules,
                path,
                report,
            } => {
                let rules_path = rules.unwrap_or_else(|| self.yara_db_path.clone());
                if !rules_path.exists() {
                    anyhow::bail!("Yara rules path does not exist: {}", rules_path.display());
                }
                let results =
                    SpireAvScanner::scan_yara_with_limits(&rules_path, &path, &self.limits)?;
                self.respond(&results, policy, m)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    println!(
                        "{}",
                        format!("Report generated at: {}", report_path.display())
                    );
                }
            }
            av_core::types::OnDemaindScanModes::YaraScan {
                rules,
                path,
                report,
            } => {
                let rules_path = rules.unwrap_or_else(|| self.yara_db_path.clone());
                if !rules_path.exists() {
                    anyhow::bail!("Yara rules path does not exist: {}", rules_path.display());
                }
                let results =
                    SpireAvScanner::scan_yara_with_limits(&rules_path, &path, &self.limits)?;
                self.respond(&results, policy, m)?;
                if let Some(report_path) = report {
                    generate_html_report(&results, &report_path, None)?;
                    println!(
                        "{}",
                        format!("Report generated at: {}", report_path.display())
                    );
                }
            }
            av_core::types::OnDemaindScanModes::ProcessScan {} => {
                unimplemented!("Not yet working!")
            }
        }
        Ok(())
    }
    fn respond(
        &self,
        results: &[av_core::core::models::ScanResult],
        policy: av_core::core::response::ResponsePolicy,
        _m: &MultiProgress,
    ) -> anyhow::Result<()> {
        for detection in results {
            if let Some(response) = av_core::core::response::respond(&self.state, detection, policy)
            {
                println!(
                    "{}",
                    format!(
                        "{}: {} {}{}",
                        response.path,
                        response.action,
                        response.status,
                        response.error.map(|e| format!(": {e}")).unwrap_or_default()
                    )
                );
            }
            if let av_core::core::models::ScanResult::Error { path, error } = detection {
                println!(
                    "{}",
                    format!("Scan incomplete {}: {}", path.display(), error)
                );
            }
        }
        Ok(())
    }
    pub fn update(url: Option<String>) -> anyhow::Result<()> {
        let cfg = SpireConfig::load()?;
        let key = cfg
            .update_public_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Configure update_public_key"))?;
        let feed = ThreatDatabase::install(
            url.as_deref()
                .or(cfg.update_url.as_deref())
                .unwrap_or("http://127.0.0.1:8080"),
            &cfg.spire_dir(),
            key,
        )?;
        println!(
            "Activated signed feed version {}. Restart running agents to load it.",
            feed.version
        );
        Ok(())
    }
    pub fn quarantine(quarantine_action: QuarantineAction) -> anyhow::Result<()> {
        let cfg = SpireConfig::load()?;
        let root = cfg.spire_dir();
        std::fs::create_dir_all(&root)?;
        let state = Connection::open(root.join("response.db"))?;
        Quarantine::init(&state)?;
        Quarantine::migrate_legacy(&state, &root.join(cfg.db_path()))?;
        match quarantine_action {
            QuarantineAction::List {} => {
                let items = Quarantine::list_quarantined(&state)?;
                let _: () = for (id, original_path, malware_name, timestamp) in items {
                    let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0)
                        .ok_or_else(|| anyhow::anyhow!("Invalid timestamp: {}", timestamp))?;
                    let cest_offset =
                        FixedOffset::east_opt(2 * 3600).expect("Invalid timezone offset");
                    let datetime_cest = datetime.with_timezone(&cest_offset);
                    println!(
                        "ID: {:<4} | Path: {} | Malware: {} | Quarantined: {}",
                        id,
                        original_path,
                        malware_name,
                        datetime_cest.format("%Y-%m-%d %H:%M:%S %Z")
                    );
                };
                Ok(())
            }
            QuarantineAction::Restore { id } => {
                Quarantine::restore_quarantined(&state, id)?;
                println!("Restored item with ID: {id}");
                Ok(())
            }
            QuarantineAction::Delete { id } => {
                Quarantine::delete_quarantined(&state, id)?;
                println!("Deleted item with ID: {id}");
                Ok(())
            }
        }
    }
}
