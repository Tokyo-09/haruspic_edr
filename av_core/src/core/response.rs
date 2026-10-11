use super::{models::ScanResult, quarantine::Quarantine};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsePolicy {
    #[default]
    Observe,
    Quarantine,
}

#[derive(Debug, Serialize)]
pub struct ResponseResult {
    pub path: String,
    pub action: &'static str,
    pub status: &'static str,
    pub error: Option<String>,
}

/// Response failures are separate from the immutable detection result.
pub fn respond(
    conn: &Connection,
    detection: &ScanResult,
    policy: ResponsePolicy,
) -> Option<ResponseResult> {
    detection.fingerprint()?;
    let path = detection.path().display().to_string();
    Some(match policy {
        ResponsePolicy::Observe => ResponseResult {
            path,
            action: "observe",
            status: "skipped",
            error: None,
        },
        ResponsePolicy::Quarantine => match Quarantine::quarantine_file(conn, detection) {
            Ok(()) => ResponseResult {
                path,
                action: "quarantine",
                status: "succeeded",
                error: None,
            },
            Err(error) => ResponseResult {
                path,
                action: "quarantine",
                status: "failed",
                error: Some(error.to_string()),
            },
        },
    })
}
