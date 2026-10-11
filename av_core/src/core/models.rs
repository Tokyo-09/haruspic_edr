use crate::core::db::ThreatDatabase;

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum ScanResult {
    Clean(PathBuf),
    Threat {
        path: PathBuf,
        malware: ThreatDatabase,
        observed_sha256: String,
    },
    YaraThreat {
        path: PathBuf,
        matching_rules: Vec<String>,
        observed_sha256: String,
    },
    Error {
        path: PathBuf,
        error: String,
    },
}

impl ScanResult {
    pub fn path(&self) -> &std::path::Path {
        match self {
            Self::Clean(path)
            | Self::Threat { path, .. }
            | Self::YaraThreat { path, .. }
            | Self::Error { path, .. } => path,
        }
    }
    pub fn fingerprint(&self) -> Option<&str> {
        match self {
            Self::Threat {
                observed_sha256, ..
            }
            | Self::YaraThreat {
                observed_sha256, ..
            } => Some(observed_sha256),
            _ => None,
        }
    }
}
