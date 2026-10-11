use crate::{
    core::{
        db::ThreatDatabase,
        limits::{ScanLimits, read_bounded},
        models::ScanResult,
    },
    modules::heuristic_scanner::SpireHeuristicEngine,
    types::{FileContainer, FileData, FileType, HeuristicResult},
    utils::{
        heuristic_analyze::{extract_ascii_strings, parse_file},
        yara::compile_yara_rules,
    },
};
use log::debug;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use walkdir::WalkDir;

pub mod core;
pub mod modules;
pub mod types;
pub mod utils;

/// Detection only: these methods never move files or issue desktop notifications.
pub struct SpireAvScanner;
impl SpireAvScanner {
    pub fn check_file(
        conn: &Connection,
        md5hash: String,
        sha256hash: String,
    ) -> anyhow::Result<Option<ThreatDatabase>> {
        use rusqlite::OptionalExtension;
        Ok(conn.query_row("SELECT md5hash, sha256hash, name FROM default_db WHERE md5hash=?1 OR sha256hash=?2 LIMIT 1",
            [md5hash, sha256hash], |row| Ok(ThreatDatabase { md5hash: row.get(0)?, sha256hash: row.get(1)?, name: row.get(2)? })).optional()?)
    }
    pub fn scan_single_file(conn: &Connection, path: PathBuf) -> anyhow::Result<ScanResult> {
        Self::scan_single_file_with_limits(conn, path, &ScanLimits::default())
    }
    pub fn scan_single_file_with_limits(
        conn: &Connection,
        path: PathBuf,
        limits: &ScanLimits,
    ) -> anyhow::Result<ScanResult> {
        limits.validate()?;
        Ok(Self::hash_detection(conn, &path, limits, limits.deadline()))
    }
    fn hash_detection(
        conn: &Connection,
        path: &Path,
        limits: &ScanLimits,
        deadline: Instant,
    ) -> ScanResult {
        let result = (|| -> anyhow::Result<ScanResult> {
            anyhow::ensure!(
                conn.query_row("SELECT EXISTS(SELECT 1 FROM default_db LIMIT 1)", [], |r| r
                    .get::<_, bool>(0))?,
                "Signature database is empty; protection degraded"
            );
            let bytes = read_bounded(path, limits.max_file_bytes, deadline)?;
            let sha256 = hex::encode(Sha256::digest(&bytes));
            let md5 = hex::encode(md5::Md5::digest(&bytes));
            match Self::check_file(conn, md5, sha256.clone())? {
                Some(malware) => Ok(ScanResult::Threat {
                    path: path.to_path_buf(),
                    malware,
                    observed_sha256: sha256,
                }),
                None => Ok(ScanResult::Clean(path.to_path_buf())),
            }
        })();
        result.unwrap_or_else(|e| ScanResult::Error {
            path: path.to_path_buf(),
            error: e.to_string(),
        })
    }
    pub fn scan_path(conn: &Connection, path: &PathBuf) -> anyhow::Result<Vec<ScanResult>> {
        Self::scan_path_with_limits(conn, path, &ScanLimits::default())
    }
    pub fn scan_path_with_limits(
        conn: &Connection,
        path: &Path,
        limits: &ScanLimits,
    ) -> anyhow::Result<Vec<ScanResult>> {
        limits.validate()?;
        let deadline = limits.deadline();
        scan_walk(path, limits, deadline, |path| {
            Self::hash_detection(conn, path, limits, deadline)
        })
    }
    pub fn scan_yara(
        _conn: &Connection,
        rules: &PathBuf,
        path: &PathBuf,
    ) -> anyhow::Result<Vec<ScanResult>> {
        Self::scan_yara_with_limits(rules, path, &ScanLimits::default())
    }
    pub fn scan_yara_with_limits(
        rules: &Path,
        path: &Path,
        limits: &ScanLimits,
    ) -> anyhow::Result<Vec<ScanResult>> {
        limits.validate()?;
        let deadline = limits.deadline();
        let compiled = compile_yara_rules(&rules.to_path_buf())?;
        let mut scanner = yara_x::Scanner::new(&compiled);
        scanner.set_timeout(Duration::from_secs(limits.yara_timeout_secs));
        scan_walk(path, limits, deadline, |path| {
            let result = (|| -> anyhow::Result<ScanResult> {
                let bytes = read_bounded(path, limits.max_file_bytes, deadline)?;
                let found = scanner.scan(&bytes)?;
                let matching_rules: Vec<String> = found
                    .matching_rules()
                    .map(|r| r.identifier().to_owned())
                    .collect();
                if matching_rules.is_empty() {
                    Ok(ScanResult::Clean(path.to_path_buf()))
                } else {
                    Ok(ScanResult::YaraThreat {
                        path: path.to_path_buf(),
                        matching_rules,
                        observed_sha256: hex::encode(Sha256::digest(&bytes)),
                    })
                }
            })();
            result.unwrap_or_else(|e| ScanResult::Error {
                path: path.to_path_buf(),
                error: e.to_string(),
            })
        })
    }
    pub fn heuristic_scan(path: &PathBuf) -> anyhow::Result<()> {
        let engine = SpireHeuristicEngine::new();

        let file_path = path;
        let limits = ScanLimits::default();
        let bytes = read_bounded(file_path, limits.max_file_bytes, limits.deadline())?;

        // Parse the file
        let file_data = match parse_file(&bytes) {
            Ok(data) => data,
            Err(_) => {
                let strings = extract_ascii_strings(&bytes, 4);
                FileData {
                    bytes,
                    file_type: FileType::Unknown,
                    strings,
                    container: FileContainer::None,
                }
            }
        };

        match engine.scan(&file_data) {
            HeuristicResult::Safe => {
                debug!("✅ Safe");
                Ok(())
            }
            HeuristicResult::Suspicious { score, reason } => {
                debug!("⚠️ Suspicious (score: {})", score);
                debug!("   Reason: {}", reason);
                Ok(())
            }
            HeuristicResult::Malicious { score, reason } => {
                debug!("❌ Malicious (score: {})", score);
                debug!("   Reason: {}", reason);
                Ok(())
            }
        }
    }
}

fn scan_walk(
    path: &Path,
    limits: &ScanLimits,
    deadline: Instant,
    mut detect: impl FnMut(&Path) -> ScanResult,
) -> anyhow::Result<Vec<ScanResult>> {
    anyhow::ensure!(path.exists(), "Scan path does not exist");
    let mut results = Vec::new();
    for (entries, entry) in WalkDir::new(path)
        .follow_links(false)
        .max_open(16)
        .into_iter()
        .enumerate()
    {
        if entries >= limits.max_entries
            || results.len() >= limits.max_files
            || Instant::now() >= deadline
        {
            results.push(ScanResult::Error {
                path: path.to_path_buf(),
                error: "Scan incomplete: entry, file or time limit reached".into(),
            });
            break;
        }
        match entry {
            Ok(entry) if entry.depth() > limits.max_depth => {
                results.push(ScanResult::Error {
                    path: entry.path().to_path_buf(),
                    error: "Scan incomplete: depth limit reached".into(),
                });
                break;
            }
            Ok(entry) if entry.file_type().is_file() => results.push(detect(entry.path())),
            Ok(_) => {}
            Err(e) => results.push(ScanResult::Error {
                path: e.path().unwrap_or(path).to_path_buf(),
                error: e.to_string(),
            }),
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::response::{ResponsePolicy, respond};
    fn database(bytes: &[u8]) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE default_db(md5hash TEXT,sha256hash TEXT,name TEXT);")
            .unwrap();
        conn.execute(
            "INSERT INTO default_db VALUES(?1,?2,'test-rule')",
            [
                hex::encode(md5::Md5::digest(bytes)),
                hex::encode(Sha256::digest(bytes)),
            ],
        )
        .unwrap();
        conn
    }
    #[test]
    fn failed_response_does_not_change_detection() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let file = root.path().join("sample");
        fs_write(&file, b"x")?;
        let conn = database(b"x");
        let detection = SpireAvScanner::scan_single_file(&conn, file.clone())?;
        std::fs::remove_file(file)?;
        let result = respond(&conn, &detection, ResponsePolicy::Quarantine).unwrap();
        assert_eq!(result.status, "failed");
        assert!(result.error.is_some());
        assert!(matches!(detection, ScanResult::Threat { .. }));
        Ok(())
    }
    #[test]
    fn hash_detection_and_observe_never_move_files() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let file = root.path().join("sample");
        fs_write(&file, b"harmless fixture")?;
        let conn = database(b"harmless fixture");
        let detection = SpireAvScanner::scan_single_file(&conn, file.clone())?;
        assert!(matches!(detection, ScanResult::Threat { .. }));
        assert_eq!(
            respond(&conn, &detection, ResponsePolicy::Observe)
                .unwrap()
                .status,
            "skipped"
        );
        assert!(file.exists());
        let tables: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='quarantine'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(tables, 0);
        Ok(())
    }
    fn fs_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }
    #[test]
    fn yara_loads_rules_and_preserves_single_and_directory_targets() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let rule = root.path().join("test.yar");
        fs_write(
            &rule,
            b"rule marker { strings: $a = \"fixture_marker\" condition: $a }",
        )?;
        let targets = root.path().join("targets");
        std::fs::create_dir(&targets)?;
        let file = targets.join("sample");
        fs_write(&file, b"fixture_marker")?;
        let limits = ScanLimits::default();
        for target in [&file, &targets] {
            let found = SpireAvScanner::scan_yara_with_limits(&rule, target, &limits)?;
            assert!(
                matches!(&found[0],ScanResult::YaraThreat {matching_rules,..} if matching_rules==&["marker"])
            );
            assert!(file.exists());
        }
        Ok(())
    }
    #[test]
    fn file_and_walk_limits_report_incomplete() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let conn = database(b"x");
        fs_write(&root.path().join("one"), b"longer than cap")?;
        fs_write(&root.path().join("two"), b"x")?;
        let limits = ScanLimits {
            max_file_bytes: 1,
            max_files: 1,
            ..ScanLimits::default()
        };
        let result =
            SpireAvScanner::scan_single_file_with_limits(&conn, root.path().join("one"), &limits)?;
        assert!(matches!(result, ScanResult::Error { .. }));
        let results = SpireAvScanner::scan_path_with_limits(&conn, root.path(), &limits)?;
        assert_eq!(results.len(), 2);
        assert!(
            matches!(results.last(),Some(ScanResult::Error {error,..}) if error.contains("incomplete"))
        );
        Ok(())
    }
    #[test]
    fn empty_database_never_reports_clean() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let file = root.path().join("sample");
        fs_write(&file, b"x")?;
        let conn = database(b"x");
        conn.execute("DELETE FROM default_db", [])?;
        assert!(
            matches!(SpireAvScanner::scan_single_file(&conn,file)?, ScanResult::Error {error,..} if error.contains("degraded"))
        );
        Ok(())
    }
}
