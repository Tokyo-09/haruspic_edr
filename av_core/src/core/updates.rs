//! Signed, bounded feeds. A SQLite pointer activates an immutable DB/YARA pair.
use anyhow::{Context, Result, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const MAX_DB_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_ZIP_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_EXPANDED_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_FEED_STORAGE: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub size: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub version: u64,
    pub expires_at: i64,
    pub database: Artifact,
    pub yara: Artifact,
}
#[derive(Debug, Clone)]
pub struct InstalledFeed {
    pub version: u64,
    pub database: PathBuf,
    pub yara_rules: PathBuf,
}

pub fn verify_manifest(
    bytes: &[u8],
    signature: &[u8],
    public_key_hex: &str,
    now: i64,
) -> Result<Manifest> {
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "Manifest too large"
    );
    let key = hex::decode(public_key_hex.trim()).context("Invalid update public key hex")?;
    ensure!(
        key.len() == 32 && signature.len() == 64,
        "Invalid Ed25519 key/signature length"
    );
    UnparsedPublicKey::new(&ED25519, key)
        .verify(bytes, signature)
        .map_err(|_| anyhow::anyhow!("Update signature verification failed"))?;
    let manifest: Manifest = serde_json::from_slice(bytes)?;
    ensure!(
        manifest.schema_version == 1 && manifest.version > 0 && manifest.version <= i64::MAX as u64,
        "Unsupported manifest/version"
    );
    ensure!(manifest.expires_at > now, "Update manifest expired");
    for (artifact, cap) in [
        (&manifest.database, MAX_DB_BYTES),
        (&manifest.yara, MAX_ZIP_BYTES),
    ] {
        ensure!(
            artifact.size > 0 && artifact.size <= cap && hex::decode(&artifact.sha256)?.len() == 32,
            "Invalid artifact size/hash"
        );
    }
    Ok(manifest)
}

fn verify_artifact(path: &Path, artifact: &Artifact) -> Result<()> {
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.len() == artifact.size,
        "Artifact size mismatch"
    );
    let mut hasher = Sha256::new();
    let read = std::io::copy(
        &mut (&mut file).take(artifact.size + 1),
        &mut DigestWriter(&mut hasher),
    )?;
    ensure!(
        read == artifact.size && hex::encode(hasher.finalize()) == artifact.sha256.to_lowercase(),
        "Artifact digest mismatch"
    );
    Ok(())
}
struct DigestWriter<'a>(&'a mut Sha256);
impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn state(root: &Path) -> Result<Connection> {
    fs::create_dir_all(root.join("feeds"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("feeds"), fs::Permissions::from_mode(0o700))?;
    }
    let conn = Connection::open(root.join("feed-state.db"))?;
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS active_feed (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, directory TEXT NOT NULL);")?;
    Ok(conn)
}
fn feed_paths(root: &Path, directory: &str, version: u64) -> Result<InstalledFeed> {
    ensure!(
        Path::new(directory).components().count() == 1 && directory.starts_with("signed-"),
        "Invalid active feed path"
    );
    let path = root.join("feeds").join(directory);
    Ok(InstalledFeed {
        version,
        database: path.join("database.db"),
        yara_rules: path.join("yara"),
    })
}

pub fn active(root: &Path, public_key: &str) -> Result<Option<InstalledFeed>> {
    let conn = state(root)?;
    let row: Option<(u64, String)> = conn
        .query_row(
            "SELECT version, directory FROM active_feed WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((version, directory)) = row else {
        return Ok(None);
    };
    let paths = feed_paths(root, &directory, version)?;
    let dir = paths.database.parent().unwrap();
    let bytes = read_small(&dir.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let sig = read_small(&dir.join("manifest.sig"), 64)?;
    let manifest = verify_manifest(&bytes, &sig, public_key, chrono::Utc::now().timestamp())?;
    ensure!(manifest.version == version, "Active version mismatch");
    verify_artifact(&paths.database, &manifest.database)?;
    verify_artifact(&dir.join("yara.zip"), &manifest.yara)?;
    Ok(Some(paths))
}
fn read_small(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.take(cap + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= cap, "File limit exceeded");
    Ok(data)
}

fn storage_used(root: &Path) -> Result<u64> {
    let mut size = 0;
    for (index, entry) in walkdir::WalkDir::new(root.join("feeds"))
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        ensure!(
            index < 20_000,
            "Feed storage entry limit exceeded; retire old releases"
        );
        let entry = entry?;
        ensure!(!entry.file_type().is_symlink(), "Symlink in feed store");
        if entry.file_type().is_file() {
            size += entry.metadata()?.len();
        }
        ensure!(
            size <= MAX_FEED_STORAGE,
            "Feed storage limit exceeded; retire old releases"
        );
    }
    Ok(size)
}

fn extract_rules(zip: &Path, target: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(File::open(zip)?)?;
    ensure!(archive.len() <= 4096, "Too many archive entries");
    let mut total = 0u64;
    fs::create_dir(target)?;
    for i in 0..archive.len() {
        let mut member = archive.by_index(i)?;
        let relative = member.enclosed_name().context("Unsafe archive path")?;
        ensure!(
            relative.components().count() <= 32,
            "Archive depth exceeded"
        );
        ensure!(
            member.unix_mode().unwrap_or(0) & 0o170000 != 0o120000,
            "Archive symlinks forbidden"
        );
        if member.is_dir() {
            continue;
        }
        ensure!(
            matches!(
                relative.extension().and_then(|e| e.to_str()),
                Some("yar" | "yara")
            ),
            "Only YARA source files allowed"
        );
        ensure!(
            member.size() <= 1024 * 1024 && total + member.size() <= MAX_EXPANDED_BYTES,
            "Expanded archive limit exceeded"
        );
        let dest = target.join(relative);
        fs::create_dir_all(dest.parent().unwrap())?;
        let mut output = File::options().write(true).create_new(true).open(&dest)?;
        let copied = std::io::copy(&mut (&mut member).take(1024 * 1024 + 1), &mut output)?;
        total += copied;
        ensure!(
            copied <= 1024 * 1024 && total <= MAX_EXPANDED_BYTES,
            "Expanded archive limit exceeded"
        );
        output.sync_all()?;
    }
    crate::utils::yara::compile_yara_rules(&target.to_path_buf())?;
    Ok(())
}
fn validate_database(path: &Path) -> Result<()> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.execute_batch("PRAGMA trusted_schema=OFF;")?;
    let kind: String = conn.query_row(
        "SELECT type FROM sqlite_master WHERE name='default_db'",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        kind == "table",
        "Signature database must contain default_db table"
    );
    let mut stmt = conn.prepare("SELECT md5hash, sha256hash, name FROM default_db LIMIT 1")?;
    ensure!(
        stmt.query([])?.next()?.is_some(),
        "Signature database must not be empty"
    );
    Ok(())
}
fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::options().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn activate(
    tx: &rusqlite::Transaction<'_>,
    root: &Path,
    stage: TempDir,
    manifest: &Manifest,
    bytes: &[u8],
    signature: &[u8],
) -> Result<InstalledFeed> {
    verify_artifact(&stage.path().join("database.db"), &manifest.database)?;
    verify_artifact(&stage.path().join("yara.zip"), &manifest.yara)?;
    validate_database(&stage.path().join("database.db"))?;
    extract_rules(&stage.path().join("yara.zip"), &stage.path().join("yara"))?;
    write_synced(&stage.path().join("manifest.json"), bytes)?;
    write_synced(&stage.path().join("manifest.sig"), signature)?;
    #[cfg(unix)]
    {
        // Sync directory entries before the durable pointer can reference them.
        for entry in walkdir::WalkDir::new(stage.path()).contents_first(true) {
            let entry = entry?;
            if entry.file_type().is_dir() {
                File::open(entry.path())?.sync_all()?;
            }
        }
        File::open(root.join("feeds"))?.sync_all()?;
    }
    ensure!(
        manifest.expires_at > chrono::Utc::now().timestamp(),
        "Update manifest expired during validation"
    );
    let directory = stage
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .context("Invalid staging directory")?
        .to_owned();
    let paths = feed_paths(root, &directory, manifest.version)?;
    // Preserve fully verified data even if commit fails; never point to removed data.
    let _ = stage.keep();
    tx.execute("INSERT INTO active_feed(id, version, directory) VALUES(1, ?1, ?2) ON CONFLICT(id) DO UPDATE SET version=excluded.version, directory=excluded.directory", rusqlite::params![manifest.version, directory])?;
    Ok(paths)
}

fn check_version(tx: &rusqlite::Transaction<'_>, version: u64) -> Result<()> {
    let previous: Option<u64> = tx
        .query_row("SELECT version FROM active_feed WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    ensure!(
        previous.is_none_or(|v| version > v),
        "Update rollback/replay rejected"
    );
    Ok(())
}

/// Validate a distributor's release without activating or modifying it.
pub fn verify_directory(directory: &Path, public_key: &str) -> Result<Manifest> {
    let bytes = read_small(&directory.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let signature = read_small(&directory.join("manifest.sig"), 64)?;
    let manifest = verify_manifest(
        &bytes,
        &signature,
        public_key,
        chrono::Utc::now().timestamp(),
    )?;
    verify_artifact(&directory.join("database.db"), &manifest.database)?;
    verify_artifact(&directory.join("yara.zip"), &manifest.yara)?;
    validate_database(&directory.join("database.db"))?;
    let temporary = tempfile::tempdir()?;
    extract_rules(&directory.join("yara.zip"), &temporary.path().join("rules"))?;
    Ok(manifest)
}

pub fn install(url: &str, root: &Path, public_key: &str) -> Result<InstalledFeed> {
    ensure!(
        hex::decode(public_key.trim())?.len() == 32,
        "Configure update_public_key before downloading updates"
    );
    let parsed = reqwest::Url::parse(url)?;
    ensure!(
        parsed.scheme() == "https"
            || (parsed.scheme() == "http"
                && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))),
        "Updates require HTTPS outside loopback"
    );
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(path) = std::env::var_os("SPIRE_CA_CERT") {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&fs::read(path)?)?);
    }
    let client = builder.build()?;
    let base = url.trim_end_matches('/');
    let get = |name: &str, cap: u64| -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        client
            .get(format!("{base}/{name}"))
            .send()?
            .error_for_status()?
            .take(cap + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= cap, "Download limit exceeded: {name}");
        Ok(bytes)
    };
    let bytes = get("manifest.json", MAX_MANIFEST_BYTES)?;
    let signature = get("manifest.sig", 64)?;
    let manifest = verify_manifest(
        &bytes,
        &signature,
        public_key,
        chrono::Utc::now().timestamp(),
    )?;
    let mut conn = state(root)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_version(&tx, manifest.version)?;
    ensure!(
        storage_used(root)?
            + manifest.database.size
            + manifest.yara.size
            + MAX_EXPANDED_BYTES
            + 2 * MAX_MANIFEST_BYTES
            <= MAX_FEED_STORAGE,
        "Feed storage quota exceeded; retire old inactive releases"
    );
    let stage = tempfile::Builder::new()
        .prefix("signed-")
        .tempdir_in(root.join("feeds"))?;
    for (name, artifact) in [
        ("database.db", &manifest.database),
        ("yara.zip", &manifest.yara),
    ] {
        let mut response = client
            .get(format!("{base}/{name}"))
            .send()?
            .error_for_status()?;
        let mut output = File::options()
            .write(true)
            .create_new(true)
            .open(stage.path().join(name))?;
        let size = std::io::copy(&mut (&mut response).take(artifact.size + 1), &mut output)?;
        ensure!(size == artifact.size, "Artifact download size mismatch");
        output.sync_all()?;
    }
    let result = activate(&tx, root, stage, &manifest, &bytes, &signature)?;
    tx.commit()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    fn key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap()
    }
    fn descriptor(path: &Path) -> Artifact {
        let bytes = fs::read(path).unwrap();
        Artifact {
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        }
    }
    fn fixture(root: &Path, version: u64) -> (Manifest, Vec<u8>, Vec<u8>) {
        let db = root.join("database.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE default_db(md5hash TEXT,sha256hash TEXT,name TEXT); INSERT INTO default_db VALUES('abc','def','fixture');").unwrap();
        drop(conn);
        let mut zip = zip::ZipWriter::new(File::create(root.join("yara.zip")).unwrap());
        zip.start_file("test.yar", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"rule test { condition: true }").unwrap();
        zip.finish().unwrap();
        let manifest = Manifest {
            schema_version: 1,
            version,
            expires_at: chrono::Utc::now().timestamp() + 3600,
            database: descriptor(&db),
            yara: descriptor(&root.join("yara.zip")),
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let sig = key().sign(&bytes).as_ref().to_vec();
        (manifest, bytes, sig)
    }
    fn local_install(
        root: &Path,
        source: &Path,
        bytes: &[u8],
        sig: &[u8],
    ) -> Result<InstalledFeed> {
        let manifest = verify_manifest(
            bytes,
            sig,
            &hex::encode(key().public_key().as_ref()),
            chrono::Utc::now().timestamp(),
        )?;
        let mut conn = state(root)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_version(&tx, manifest.version)?;
        let stage = tempfile::Builder::new()
            .prefix("signed-")
            .tempdir_in(root.join("feeds"))?;
        fs::copy(source.join("database.db"), stage.path().join("database.db"))?;
        fs::copy(source.join("yara.zip"), stage.path().join("yara.zip"))?;
        let paths = activate(&tx, root, stage, &manifest, bytes, sig)?;
        tx.commit()?;
        Ok(paths)
    }
    #[test]
    fn signature_wrong_key_tamper_and_expiration_are_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (manifest, bytes, sig) = fixture(root.path(), 1);
        let public = hex::encode(key().public_key().as_ref());
        assert!(verify_manifest(&bytes, &sig, &public, manifest.expires_at - 1).is_ok());
        assert!(verify_manifest(&bytes, &sig, &public, manifest.expires_at).is_err());
        assert!(verify_manifest(&bytes, &sig, &"00".repeat(32), 0).is_err());
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert!(verify_manifest(&changed, &sig, &public, 0).is_err());
        assert!(verify_manifest(&bytes, &[], &public, 0).is_err());
        Ok(())
    }
    #[test]
    fn activation_is_atomic_and_rollback_replay_and_artifact_tamper_fail() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = tempfile::tempdir()?;
        let (mut manifest, bytes, sig) = fixture(source.path(), 2);
        let first = local_install(root.path(), source.path(), &bytes, &sig)?;
        assert!(first.database.exists() && first.yara_rules.join("test.yar").exists());
        assert!(local_install(root.path(), source.path(), &bytes, &sig).is_err());
        manifest.version = 1;
        let downgrade = serde_json::to_vec(&manifest)?;
        assert!(
            local_install(
                root.path(),
                source.path(),
                &downgrade,
                key().sign(&downgrade).as_ref()
            )
            .is_err()
        );
        manifest.version = 3;
        let next = serde_json::to_vec(&manifest)?;
        fs::write(source.path().join("database.db"), b"tampered")?;
        assert!(
            local_install(
                root.path(),
                source.path(),
                &next,
                key().sign(&next).as_ref()
            )
            .is_err()
        );
        assert_eq!(
            active(root.path(), &hex::encode(key().public_key().as_ref()))?
                .unwrap()
                .version,
            2
        );
        Ok(())
    }
    #[test]
    fn invalid_yara_does_not_replace_active_feed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let source = tempfile::tempdir()?;
        let (mut manifest, bytes, sig) = fixture(source.path(), 1);
        local_install(root.path(), source.path(), &bytes, &sig)?;
        let mut zip = zip::ZipWriter::new(File::create(source.path().join("yara.zip"))?);
        zip.start_file("bad.yar", zip::write::SimpleFileOptions::default())?;
        zip.write_all(b"invalid YARA source")?;
        zip.finish()?;
        manifest.version = 2;
        manifest.yara = descriptor(&source.path().join("yara.zip"));
        let next = serde_json::to_vec(&manifest)?;
        assert!(
            local_install(
                root.path(),
                source.path(),
                &next,
                key().sign(&next).as_ref()
            )
            .is_err()
        );
        assert_eq!(
            active(root.path(), &hex::encode(key().public_key().as_ref()))?
                .unwrap()
                .version,
            1
        );
        Ok(())
    }
    #[test]
    fn archive_traversal_and_expansion_limit_are_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        for (name, bytes, target) in [
            ("../escape.yar", vec![b'x'; 10], "first"),
            ("big.yar", vec![b'x'; 1024 * 1024 + 1], "second"),
        ] {
            let zip_path = root.path().join(format!("{target}.zip"));
            let mut zip = zip::ZipWriter::new(File::create(&zip_path)?);
            zip.start_file(name, zip::write::SimpleFileOptions::default())?;
            zip.write_all(&bytes)?;
            zip.finish()?;
            assert!(extract_rules(&zip_path, &root.path().join(target)).is_err());
        }
        assert!(!root.path().join("escape.yar").exists());
        Ok(())
    }
}
