use std::{sync::mpsc::sync_channel, time::Duration};

use av_core::SpireAvScanner;
use log::{debug, error, info};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::Connection;

use crate::{Config, telemetry::TelemetryHub, utils::should_monitor_path};

pub fn monitor_directory(
    conn: &Connection,
    response_db: &Connection,
    config: Config,
    limits: av_core::core::limits::ScanLimits,
    telemetry: Option<TelemetryHub>,
) -> anyhow::Result<()> {
    let (tx, rx) = sync_channel(1024);
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let callback_dropped = dropped.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            debug!("Received filesystem event: {:?}", res);
            if tx.try_send(res).is_err() {
                callback_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(1)),
    )?;

    let directories = if config.watch_paths.is_empty() {
        vec![
            dirs::home_dir(),
            dirs::audio_dir(),
            dirs::cache_dir(),
            dirs::data_dir(),
            dirs::config_local_dir(),
            dirs::config_dir(),
            dirs::document_dir(),
            dirs::download_dir(),
            dirs::executable_dir(),
            dirs::picture_dir(),
            dirs::preference_dir(),
            dirs::public_dir(),
            dirs::state_dir(),
            dirs::template_dir(),
            dirs::video_dir(),
        ]
    } else {
        config.watch_paths.iter().cloned().map(Some).collect()
    };

    debug!("monitoring: {:?}", directories);

    let mut watched = 0;
    for dir in directories {
        match dir {
            Some(path) => {
                if path.exists() {
                    match watcher.watch(&path, RecursiveMode::Recursive) {
                        Ok(_) => {
                            watched += 1;
                            info!("Monitoring directory: {}", path.display());
                        }
                        Err(e) => error!(
                            "Failed to watch directory {}: {} (continuing without it)",
                            path.display(),
                            e
                        ),
                    }
                } else {
                    debug!("Directory does not exist, skipping: {}", path.display());
                }
            }
            None => {
                debug!("Directory not found, skipping");
            }
        }
    }

    anyhow::ensure!(watched > 0, "No configured directory could be monitored");
    if let Some(path) = std::env::var_os("SPIRE_READY_FILE") {
        let path = std::path::PathBuf::from(path);
        anyhow::ensure!(path.is_absolute(), "Ready file path must be absolute");
        std::fs::write(path, std::process::id().to_string())?;
    }
    info!("Starting event loop");
    for res in rx {
        let lost = dropped.swap(0, std::sync::atomic::Ordering::Relaxed);
        if lost > 0 {
            log::warn!("Filesystem event buffer overflow: {lost} events dropped");
            if let Some(hub) = &telemetry {
                hub.emit(crate::telemetry::TelemetryEvent::new(
                    "agent_status",
                    "high",
                    serde_json::json!({"file_events_dropped":lost}),
                ));
            }
        }
        debug!("Processing event: {:?}", res);
        match res {
            Ok(event) => {
                debug!("Event kind: {:?}", event.kind);
                if event.kind.is_create() || event.kind.is_modify() {
                    let action = if event.kind.is_create() {
                        "create"
                    } else {
                        "modify"
                    };
                    for file_path in event.paths {
                        debug!("Checking path: {}", file_path.display());
                        if file_path.is_file() {
                            let parent = file_path.parent().unwrap_or(&file_path);
                            if should_monitor_path(parent, &config)
                                && should_monitor_path(&file_path, &config)
                            {
                                info!("Detected change in file: {:?}", file_path);
                                if let Some(hub) = &telemetry {
                                    hub.file_event(&file_path.display().to_string(), action);
                                }
                                match SpireAvScanner::scan_single_file_with_limits(
                                    conn, file_path, &limits,
                                ) {
                                    Ok(result) => {
                                        if let Some(hub) = &telemetry {
                                            hub.scan_result(&result);
                                        }
                                        if let Some(response) = av_core::core::response::respond(
                                            response_db,
                                            &result,
                                            config.response_policy,
                                        ) {
                                            if response.status == "failed" {
                                                error!("Response failed: {:?}", response.error);
                                            }
                                            if let Some(hub) = &telemetry {
                                                hub.emit(crate::telemetry::TelemetryEvent::new(
                                                "response_result", if response.status == "failed" { "high" } else { "info" },
                                                serde_json::json!({"path":response.path, "action":response.action, "status":response.status, "error":response.error, "sha256":result.fingerprint()})));
                                            }
                                        }
                                    }
                                    Err(e) => error!("Error scanning file  {}", e),
                                }
                            } else {
                                debug!(
                                    "Skipping file in unmonitored directory: {}",
                                    file_path.display()
                                );
                            }
                        }
                    }
                } else {
                    debug!("Ignoring event kind: {:?}", event.kind);
                }
            }
            Err(e) => {
                error!("Filesystem watch error: {}", e);
            }
        }
    }

    Ok(())
}
