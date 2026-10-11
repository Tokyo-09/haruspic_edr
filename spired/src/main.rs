use av_core::core::{config::Config as SpireConfig, db::ThreatDatabase};
use clap::Parser;
use env_logger::Builder;
use log::{LevelFilter, debug, info};
use rusqlite::Connection;
use serde::Deserialize;
use std::path::PathBuf;

use crate::{
    commands::Cli,
    monitor::monitor_directory,
    telemetry::{TelemetryConfig, spawn},
    utils::load_config,
};

pub mod commands;
pub mod inventory;
pub mod monitor;
pub mod queue;
pub mod telemetry;
pub mod utils;

#[derive(Deserialize)]
pub struct Config {
    #[serde(default)]
    pub watch_paths: Vec<PathBuf>,
    pub excluded_paths: Vec<PathBuf>,
    pub excluded_extensions: Vec<String>,
    pub excluded_files: Vec<String>,
    #[serde(default)]
    pub telemetry: bool,
    #[serde(default = "default_telemetry_url")]
    pub telemetry_url: String,
    #[serde(default = "default_enrollment_token")]
    pub enrollment_token: String,
    #[serde(default)]
    pub response_policy: av_core::core::response::ResponsePolicy,
    #[serde(default)]
    pub queue_limits: queue::QueueLimits,
}

fn default_telemetry_url() -> String {
    "http://127.0.0.1:8080".into()
}

fn default_enrollment_token() -> String {
    String::new()
}

fn main() -> anyhow::Result<()> {
    let config = load_config()?;

    let args = Cli::parse();
    let log_level = match args.verbose {
        0 => LevelFilter::Off,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    Builder::new().filter_level(log_level).init();
    info!("Logging initialized with level {:?}", log_level);

    let cfg = SpireConfig::load()?;
    cfg.scan_limits.validate()?;
    let spire_dir = cfg.spire_dir();
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
    let queue_path = spire_dir.join("telemetry-queue.db");
    let conn = Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let response_db = Connection::open(spire_dir.join("response.db"))?;
    av_core::core::quarantine::Quarantine::init(&response_db)?;
    av_core::core::quarantine::Quarantine::migrate_legacy(
        &response_db,
        &spire_dir.join(cfg.db_path()),
    )?;
    debug!("Active signed feed version {}", feed.version);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let telemetry = {
        let _guard = rt.enter();
        spawn(TelemetryConfig {
            enabled: config.telemetry,
            server_url: config.telemetry_url.clone(),
            enrollment_token: config.enrollment_token.clone(),
            queue_path,
            db_path: db_path.clone(),
            scan_limits: cfg.scan_limits.clone(),
            queue_limits: config.queue_limits.clone(),
        })
    };

    monitor_directory(&conn, &response_db, config, cfg.scan_limits, telemetry)?;
    drop(rt);
    Ok(())
}
