use anyhow::{Result, ensure};
use av_core::core::updates::{Artifact, MAX_DB_BYTES, MAX_ZIP_BYTES, Manifest};
use clap::{Parser, Subcommand};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Verify a prepared release using a trusted public key file.
    Verify {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Sign {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        yara: PathBuf,
        #[arg(long)]
        version: u64,
        /// Expiration as Unix UTC seconds.
        #[arg(long)]
        expires_at: i64,
        /// New release directory. Existing directories are never overwritten.
        #[arg(long)]
        out: PathBuf,
    },
}
fn write_new(path: &PathBuf, bytes: &[u8], private: bool) -> Result<()> {
    let mut options = File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn copy_artifact(from: &PathBuf, to: &PathBuf, cap: u64) -> Result<Artifact> {
    let mut source = File::open(from)?;
    ensure!(
        source.metadata()?.len() <= cap,
        "Artifact exceeds size limit"
    );
    let mut output = File::options().write(true).create_new(true).open(to)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut block = [0; 65536];
    loop {
        let n = source.read(&mut block)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        ensure!(size <= cap, "Artifact exceeds size limit");
        output.write_all(&block[..n])?;
        hash.update(&block[..n]);
    }
    output.sync_all()?;
    Ok(Artifact {
        size,
        sha256: hex::encode(hash.finalize()),
    })
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Verify {
            directory,
            public_key,
        } => {
            let key = fs::read_to_string(public_key)?;
            let manifest = av_core::core::updates::verify_directory(&directory, key.trim())?;
            println!("Verified feed version {}", manifest.version);
        }
        Command::Keygen {
            private_key,
            public_key,
        } => {
            ensure!(
                !private_key.exists() && !public_key.exists(),
                "Key output already exists"
            );
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| anyhow::anyhow!("Key generation failed"))?;
            let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .map_err(|_| anyhow::anyhow!("Invalid key"))?;
            write_new(&private_key, pkcs8.as_ref(), true)?;
            write_new(
                &public_key,
                hex::encode(key.public_key().as_ref()).as_bytes(),
                false,
            )?;
        }
        Command::Sign {
            private_key,
            database,
            yara,
            version,
            expires_at,
            out,
        } => {
            ensure!(
                version > 0
                    && version <= i64::MAX as u64
                    && expires_at > chrono::Utc::now().timestamp(),
                "Invalid version/expiry"
            );
            let key = Ed25519KeyPair::from_pkcs8(&fs::read(private_key)?)
                .map_err(|_| anyhow::anyhow!("Invalid private key"))?;
            fs::create_dir(&out)?;
            let manifest = Manifest {
                schema_version: 1,
                version,
                expires_at,
                database: copy_artifact(&database, &out.join("database.db"), MAX_DB_BYTES)?,
                yara: copy_artifact(&yara, &out.join("yara.zip"), MAX_ZIP_BYTES)?,
            };
            let bytes = serde_json::to_vec_pretty(&manifest)?;
            let sig = key.sign(&bytes);
            write_new(&out.join("manifest.json"), &bytes, false)?;
            // Publishing manifest.sig last marks a complete signed release.
            write_new(&out.join("manifest.sig"), sig.as_ref(), false)?;
            println!("Signed feed {} created at {}", version, out.display());
        }
    }
    Ok(())
}
