use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanLimits {
    pub max_file_bytes: u64,
    pub max_files: usize,
    pub max_entries: usize,
    pub max_depth: usize,
    pub timeout_secs: u64,
    pub yara_timeout_secs: u64,
}
impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024,
            max_files: 10_000,
            max_entries: 50_000,
            max_depth: 64,
            timeout_secs: 120,
            yara_timeout_secs: 2,
        }
    }
}
impl ScanLimits {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_file_bytes > 0
                && self.max_file_bytes <= 256 * 1024 * 1024
                && self.max_files > 0
                && self.max_files <= 100_000
                && self.max_entries > 0
                && self.max_entries <= 1_000_000
                && self.max_depth > 0
                && self.max_depth <= 128
                && self.timeout_secs > 0
                && self.timeout_secs <= 3600
                && self.yara_timeout_secs > 0
                && self.yara_timeout_secs <= 30,
            "Invalid scan limits"
        );
        Ok(())
    }
    pub fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(self.timeout_secs)
    }
}

/// A byte limit enforced while reading also covers files growing after stat().
pub fn read_bounded(path: &Path, max_bytes: u64, deadline: Instant) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        std::fs::symlink_metadata(path)?.is_file(),
        "Not a regular file (symlinks are excluded)"
    );
    let mut file = File::open(path)?;
    anyhow::ensure!(file.metadata()?.is_file(), "Not a regular file");
    anyhow::ensure!(
        file.metadata()?.len() <= max_bytes,
        "File byte limit exceeded"
    );
    let mut bytes = Vec::new();
    let mut block = [0u8; 64 * 1024];
    loop {
        anyhow::ensure!(Instant::now() < deadline, "Scan deadline exceeded");
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        anyhow::ensure!(
            bytes.len() as u64 + n as u64 <= max_bytes,
            "File byte limit exceeded"
        );
        bytes.extend_from_slice(&block[..n]);
    }
    Ok(bytes)
}
