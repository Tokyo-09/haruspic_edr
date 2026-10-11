use hex;
use md5::{Digest, Md5};
use sha2::Sha256;
use std::{fs::File, io::Read, path::PathBuf};

pub struct Hasher;

impl Hasher {
    pub fn calculate_hashes(file: PathBuf) -> anyhow::Result<(String, String)> {
        let file = file.canonicalize().map_err(|e| {
            anyhow::anyhow!("Failed to canonicalize path {}: {}", file.display(), e)
        })?;

        if !file.is_file() {
            anyhow::bail!("Path is not a file: {}", file.display());
        }

        // Implement This To All Types Of Scan
        let metadata = file
            .metadata()
            .map_err(|e| anyhow::anyhow!("Failed to get metadata for {}: {}", file.display(), e))?;

        if metadata.len() == 0 {
            log::warn!("Skipping empty file: {}", file.display());
            return Ok(("".to_string(), "".to_string())); // Or return an error
        }
        if metadata.len() > 1_000_000_000 {
            log::warn!("Skipping huge file (over 1GB): {}", file.display());
            anyhow::bail!("File too large to hash: {}", file.display());
        }

        let mut file = File::open(&file)?;
        let mut md5_hasher = Md5::new();
        let mut sha256_hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            md5_hasher.update(&buffer[..bytes_read]);
            sha256_hasher.update(&buffer[..bytes_read]);
        }

        let md5_hash = format!("{:x}", md5_hasher.finalize());
        let sha256_hash = hex::encode(sha256_hasher.finalize());

        Ok((md5_hash, sha256_hash))
    }

    pub fn calculate_md5(file: PathBuf) -> anyhow::Result<String> {
        let (md5, _) = Self::calculate_hashes(file)?;
        Ok(md5)
    }

    pub fn calculate_sha256(file: PathBuf) -> anyhow::Result<String> {
        let (_, sha256) = Self::calculate_hashes(file)?;
        Ok(sha256)
    }
}
