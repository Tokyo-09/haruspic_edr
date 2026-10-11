use std::{
    env, fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use av_core::SpireAvScanner;
use av_core::core::models::ScanResult;
use chrono::Utc;
use log::{debug, error, info, warn};
use reqwest::Client;
use rusqlite::Connection as SqlConnection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{inventory::process_snapshot, queue::EventQueue};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String,
    pub ts: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub severity: String,
    pub data: Value,
}

impl TelemetryEvent {
    pub fn new(event_type: &str, severity: &str, data: Value) -> Self {
        Self {
            id: new_id(),
            ts: Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            data,
        }
    }
}

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    agent_id: String,
    agent_token: String,
}

#[derive(Debug, Deserialize)]
struct RemoteCommand {
    id: String,
    command_type: String,
    payload: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct ServerPolicy {
    #[serde(default = "default_true")]
    send_heartbeat: bool,
    #[serde(default = "default_true")]
    send_host_info: bool,
    #[serde(default)]
    send_file_events: bool,
    #[serde(default)]
    send_clean_scans: bool,
    #[serde(default = "default_true")]
    send_detections: bool,
    #[serde(default = "default_true")]
    send_command_results: bool,
    #[serde(default = "default_sample")]
    file_event_sample_percent: u8,
}

fn default_true() -> bool {
    true
}
fn default_sample() -> u8 {
    10
}

impl Default for ServerPolicy {
    fn default() -> Self {
        Self {
            send_heartbeat: true,
            send_host_info: true,
            send_file_events: false,
            send_clean_scans: false,
            send_detections: true,
            send_command_results: true,
            file_event_sample_percent: 10,
        }
    }
}

fn allow_event(event: &TelemetryEvent, policy: &ServerPolicy) -> bool {
    match event.event_type.as_str() {
        "heartbeat" => policy.send_heartbeat,
        "host_info" => policy.send_host_info,
        "file_event" => policy.send_file_events && sample(policy.file_event_sample_percent),
        "scan_result" => {
            let verdict = event.data.get("verdict").and_then(|v| v.as_str());
            if verdict == Some("clean") {
                policy.send_clean_scans
            } else {
                true
            }
        }
        "detection" => policy.send_detections,
        "command_result" => policy.send_command_results,
        _ => true,
    }
}

fn sample(percent: u8) -> bool {
    if percent >= 100 {
        return true;
    }
    if percent == 0 {
        return false;
    }
    (Utc::now().timestamp_subsec_nanos() % 100) < u32::from(percent)
}

#[derive(Clone)]
pub struct TelemetryHub {
    queue: Arc<Mutex<EventQueue>>,
    policy: Arc<Mutex<ServerPolicy>>,
    enabled: Arc<AtomicBool>,
}

impl TelemetryHub {
    pub fn emit(&self, event: TelemetryEvent) {
        if !self.enabled.load(Ordering::Relaxed)
            || !allow_event(&event, &self.policy.lock().unwrap())
        {
            return;
        }
        if let Err(e) = self.queue.lock().unwrap().enqueue(&event) {
            error!("Cannot persist telemetry event: {e:#}");
        }
    }

    pub fn file_event(&self, path: &str, action: &str) {
        self.emit(TelemetryEvent::new(
            "file_event",
            "info",
            json!({ "path": path, "action": action }),
        ));
    }

    pub fn scan_result(&self, result: &ScanResult) {
        match result {
            ScanResult::Clean(path) => self.emit(TelemetryEvent::new(
                "scan_result",
                "info",
                json!({ "path": path.display().to_string(), "verdict": "clean" }),
            )),
            ScanResult::Threat {
                path,
                malware,
                observed_sha256,
            } => self.emit(TelemetryEvent::new(
                "detection",
                "high",
                json!({
                    "path": path.display().to_string(),
                    "verdict": "threat",
                    "malware_name": malware.name,
                    "md5": malware.md5hash,
                    "sha256": observed_sha256,
                }),
            )),
            ScanResult::YaraThreat {
                path,
                matching_rules,
                observed_sha256,
            } => self.emit(TelemetryEvent::new(
                "detection",
                "high",
                json!({
                    "path": path.display().to_string(),
                    "verdict": "yara",
                    "malware_name": matching_rules.join(","),
                    "sha256": observed_sha256,
                }),
            )),
            ScanResult::Error { path, error } => self.emit(TelemetryEvent::new(
                "scan_result",
                "low",
                json!({ "path": path.display().to_string(), "verdict": "error", "error": error }),
            )),
        }
    }
}

#[derive(Clone)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub server_url: String,
    pub enrollment_token: String,
    pub queue_path: PathBuf,
    pub db_path: PathBuf,
    pub scan_limits: av_core::core::limits::ScanLimits,
    pub queue_limits: crate::queue::QueueLimits,
}

pub fn spawn(cfg: TelemetryConfig) -> Option<TelemetryHub> {
    if !cfg.enabled {
        info!("Telemetry disabled (set telemetry=true or SPIRE_TELEMETRY=1)");
        return None;
    }

    if let Err(e) = validate_server_url(&cfg.server_url) {
        error!("Invalid telemetry URL: {e:#}");
        return None;
    }
    let queue = match EventQueue::open_with_limits(cfg.queue_path.clone(), cfg.queue_limits.clone())
    {
        Ok(queue) => Arc::new(Mutex::new(queue)),
        Err(e) => {
            error!("Cannot open telemetry queue: {e:#}");
            return None;
        }
    };
    let hub = TelemetryHub {
        queue,
        policy: Arc::new(Mutex::new(ServerPolicy::default())),
        enabled: Arc::new(AtomicBool::new(true)),
    };
    let worker_hub = hub.clone();
    tokio::spawn(async move {
        if let Err(e) = run_worker(cfg, worker_hub).await {
            error!("telemetry worker stopped: {e:#}");
        }
    });
    Some(hub)
}

fn validate_server_url(value: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value)?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "HTTPS is required outside loopback"
    );
    Ok(())
}

async fn run_worker(cfg: TelemetryConfig, hub: TelemetryHub) -> anyhow::Result<()> {
    let mut builder = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10));
    if let Some(path) = env::var_os("SPIRE_CA_CERT") {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(path)?)?);
    }
    let client = builder.build()?;
    let queue = EventQueue::open_with_limits(cfg.queue_path.clone(), cfg.queue_limits.clone())?;
    let state_path = identity_path()?;
    let stored = load_identity(&state_path);
    let mut agent_token = stored.agent_token;

    if let Err(e) = queue.enqueue(&TelemetryEvent::new(
        "host_info",
        "info",
        json!({
            "hostname": hostname(),
            "os": env::consts::OS,
            "arch": env::consts::ARCH,
            "agent_version": AGENT_VERSION,
        }),
    )) {
        warn!("Host info persistence: {e:#}");
    }

    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    let mut flush = tokio::time::interval(Duration::from_secs(5));
    let mut commands = tokio::time::interval(Duration::from_secs(10));
    let mut policy_tick = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let event = TelemetryEvent::new(
                    "heartbeat",
                    "info",
                    json!({
                        "hostname": hostname(),
                        "agent_version": AGENT_VERSION,
                        "queue_depth": queue.len().unwrap_or(0),
                        "queue_dropped": queue.dropped().unwrap_or(0),
                    }),
                );
                if allow_event(&event, &hub.policy.lock().unwrap()) {
                    if let Err(e) = queue.enqueue(&event) { warn!("Telemetry persistence: {e:#}"); }
                }
            }
            _ = flush.tick() => {
                if agent_token.is_none() {
                    match enroll(&client, &cfg, &state_path).await {
                        Ok((_, token)) => agent_token = Some(token),
                        Err(e) => { warn!("Enrollment unavailable; events remain on disk: {e:#}"); continue; }
                    }
                }
                let token = agent_token.as_deref().unwrap();
                let batch = queue.peek(100)?;
                if batch.is_empty() {
                    continue;
                }
                match send_batch(&client, &cfg.server_url, token, &batch).await {
                    Ok(()) => {
                        let ids: Vec<String> = batch.iter().map(|e| e.id.clone()).collect();
                        queue.ack(&ids)?;
                    }
                    Err(e) => warn!("telemetry flush failed ({} events stay queued): {e:#}", batch.len()),
                }
            }
            _ = commands.tick() => {
                let Some(token) = agent_token.as_deref() else { continue; };
                match poll_commands(&client, &cfg, token).await {
                    Ok(events) => {
                        for event in events {
                            if allow_event(&event, &hub.policy.lock().unwrap()) {
                                if let Err(e) = queue.enqueue(&event) { warn!("Telemetry persistence: {e:#}"); }
                            }
                        }
                    }
                    Err(e) => debug!("command poll: {e:#}"),
                }
            }
            _ = policy_tick.tick() => {
                let Some(token) = agent_token.as_deref() else { continue; };
                if let Ok(next) = fetch_policy(&client, &cfg.server_url, token).await {
                    *hub.policy.lock().unwrap() = next;
                }
            }
        }
    }
}

async fn response_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
    cap: usize,
) -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            bytes.len() + chunk.len() <= cap,
            "Server response limit exceeded"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn fetch_policy(
    client: &Client,
    server_url: &str,
    token: &str,
) -> anyhow::Result<ServerPolicy> {
    let url = format!("{}/v1/runtime/policy", server_url.trim_end_matches('/'));
    let response = client.get(url).bearer_auth(token).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("policy {}", response.status());
    }
    response_json(response, 1024 * 1024).await
}

async fn poll_commands(
    client: &Client,
    cfg: &TelemetryConfig,
    token: &str,
) -> anyhow::Result<Vec<TelemetryEvent>> {
    let url = format!(
        "{}/v1/agents/commands",
        cfg.server_url.trim_end_matches('/')
    );
    let response = client.get(url).bearer_auth(token).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("commands {}", response.status());
    }
    let commands: Vec<RemoteCommand> = response_json(response, 1024 * 1024).await?;
    let mut events = Vec::new();
    let journal = EventQueue::open_with_limits(cfg.queue_path.clone(), cfg.queue_limits.clone())?;
    for cmd in commands {
        let cached = journal.command_result(&cmd.id)?;
        let result = if let Some((status, payload)) = cached {
            send_command_ack(client, cfg, token, &cmd.id, &status, &payload).await?;
            continue;
        } else if !journal.claim_command(&cmd.id)? {
            Err(anyhow::anyhow!(
                "Previous execution interrupted; manual reconciliation required"
            ))
        } else {
            execute_command(cfg, &cmd).await
        };
        let (status, payload) = match result {
            Ok(value) => ("acked", value),
            Err(e) => ("failed", json!({ "error": e.to_string() })),
        };
        let payload = if serde_json::to_vec(&payload)?.len() > 256 * 1024 {
            json!({"truncated":true, "message":"Command result exceeded 256 KiB"})
        } else {
            payload
        };
        journal.finish_command(&cmd.id, status, &payload)?;
        send_command_ack(client, cfg, token, &cmd.id, status, &payload).await?;
        events.push(TelemetryEvent::new(
            "command_result",
            if status == "acked" { "info" } else { "low" },
            json!({ "command_id": cmd.id, "type": cmd.command_type, "result": payload }),
        ));
    }
    Ok(events)
}

async fn send_command_ack(
    client: &Client,
    cfg: &TelemetryConfig,
    token: &str,
    id: &str,
    status: &str,
    payload: &Value,
) -> anyhow::Result<()> {
    client
        .post(format!(
            "{}/v1/agents/commands/{}/ack",
            cfg.server_url.trim_end_matches('/'),
            id
        ))
        .bearer_auth(token)
        .json(&json!({"status": status, "result": payload}))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn execute_command(cfg: &TelemetryConfig, cmd: &RemoteCommand) -> anyhow::Result<Value> {
    match cmd.command_type.as_str() {
        "ping" => Ok(json!({ "pong": true, "ts": Utc::now().to_rfc3339() })),
        "collect_inventory" => Ok(process_snapshot()),
        "scan_path" => {
            let path = cmd
                .payload
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("scan_path requires payload.path"))?
                .to_string();
            let db_path = cfg.db_path.clone();
            let scan_limits = cfg.scan_limits.clone();
            let outcome = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
                let conn = SqlConnection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let results = SpireAvScanner::scan_path_with_limits(&conn, &PathBuf::from(&path), &scan_limits)?;
                let threats: Vec<String> = results
                    .iter()
                    .filter_map(|r| match r {
                        ScanResult::Threat { path, malware, .. } => {
                            Some(format!("{}:{}", path.display(), malware.name))
                        }
                        ScanResult::YaraThreat {
                            path,
                            matching_rules,
                            ..
                        } => Some(format!("{}:{}", path.display(), matching_rules.join(","))),
                        _ => None,
                    })
                    .collect();
                Ok(json!({
                    "path": path,
                    "scanned": results.len(),
                    "complete": !results.iter().any(|r| matches!(r, ScanResult::Error {..})),
                    "errors": results.iter().filter_map(|r| match r { ScanResult::Error {path,error} => Some(format!("{}: {error}",path.display())), _=>None }).take(100).collect::<Vec<_>>(),
                    "response_policy": "observe",
                    "threats": threats,
                }))
            })
            .await??;
            Ok(outcome)
        }

        other => anyhow::bail!("unsupported command {other}"),
    }
}

#[derive(Serialize, Deserialize, Default)]
struct StoredIdentity {
    agent_id: Option<String>,
    agent_token: Option<String>,
}

async fn enroll(
    client: &Client,
    cfg: &TelemetryConfig,
    state_path: &PathBuf,
) -> anyhow::Result<(String, String)> {
    let url = format!("{}/v1/agents/enroll", cfg.server_url.trim_end_matches('/'));
    let body = json!({
        "hostname": hostname(),
        "os_name": env::consts::OS,
        "arch": env::consts::ARCH,
        "agent_version": AGENT_VERSION,
    });

    info!("Enrolling at {url}");
    let response = client
        .post(&url)
        .header("X-Enrollment-Token", &cfg.enrollment_token)
        .json(&body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        anyhow::bail!("enroll failed: {status}");
    }

    let enrolled: EnrollResponse = response_json(response, 16 * 1024).await?;
    fs::create_dir_all(state_path.parent().unwrap())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            state_path.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )?;
    }
    let temporary = state_path.with_extension(format!("{}.tmp", new_id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    use std::io::Write;
    file.write_all(
        serde_json::to_string_pretty(&StoredIdentity {
            agent_id: Some(enrolled.agent_id.clone()),
            agent_token: Some(enrolled.agent_token.clone()),
        })?
        .as_bytes(),
    )?;
    file.sync_all()?;
    fs::rename(temporary, state_path)?;
    Ok((enrolled.agent_id, enrolled.agent_token))
}

async fn send_batch(
    client: &Client,
    server_url: &str,
    token: &str,
    events: &[TelemetryEvent],
) -> anyhow::Result<()> {
    let url = format!("{}/v1/telemetry/ingest", server_url.trim_end_matches('/'));
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&json!({
            "schema_version": 1,
            "events": events,
        }))
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("ingest {}", response.status());
    }
    debug!("flushed {} telemetry events", events.len());
    Ok(())
}

fn identity_path() -> anyhow::Result<PathBuf> {
    if let Some(dir) = env::var_os("SPIRE_STATE_DIR") {
        let dir = PathBuf::from(dir);
        anyhow::ensure!(dir.is_absolute(), "SPIRE_STATE_DIR must be absolute");
        return Ok(dir.join("agent_identity.json"));
    }
    let mut dir = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push("spire");
    Ok(dir.join("agent_identity.json"))
}

fn load_identity(path: &PathBuf) -> StoredIdentity {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn hostname() -> String {
    env::var("HOSTNAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown-host".into())
}

fn new_id() -> String {
    format!(
        "{:x}-{:x}",
        Utc::now().timestamp_nanos_opt().unwrap_or(0),
        std::process::id()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn insecure_remote_transport_is_rejected() {
        assert!(validate_server_url("http://example.com").is_err());
        assert!(validate_server_url("https://example.com").is_ok());
        assert!(validate_server_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_server_url("http://[::1]:8080").is_ok());
    }

    #[test]
    fn hub_persists_without_a_network_worker() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "spire-hub-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let path = root.join("queue.db");
        let event = TelemetryEvent::new("detection", "high", json!({}));
        let id = event.id.clone();
        {
            let hub = TelemetryHub {
                queue: Arc::new(Mutex::new(EventQueue::open(path.clone())?)),
                policy: Arc::new(Mutex::new(ServerPolicy::default())),
                enabled: Arc::new(AtomicBool::new(true)),
            };
            hub.emit(event);
        }
        {
            let queue = EventQueue::open(path)?;
            assert_eq!(queue.peek(100)?[0].id, id);
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
