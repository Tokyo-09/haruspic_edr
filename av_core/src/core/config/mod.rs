use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Config {
    pub spire_dir: Option<String>,
    pub db_path: Option<String>,
    pub yara_rules_path: Option<String>,
    pub log_level: Option<String>,
    #[serde(default)]
    pub scan_limits: super::limits::ScanLimits,
    pub update_url: Option<String>,
    pub update_public_key: Option<String>,
}

impl Config {
    pub fn load_from<P: Into<PathBuf>>(path: P) -> Result<Self> {
        let config_path = path.into();

        if config_path.exists() {
            let config_str = fs::read_to_string(&config_path).with_context(|| {
                format!("Failed to read config file: {}", config_path.display())
            })?;

            serde_json::from_str(&config_str)
                .with_context(|| format!("Failed to parse JSON config: {}", config_path.display()))
        } else {
            log::debug!(
                "Config file {} not found, using default configuration",
                config_path.display()
            );
            Ok(Self::default())
        }
    }

    pub fn load() -> Result<Self> {
        if let Some(path) = std::env::var_os("SPIRE_CONFIG_PATH") {
            let path = PathBuf::from(path);
            anyhow::ensure!(
                path.is_file(),
                "Configured core file is missing: {}",
                path.display()
            );
            Self::load_from(path)
        } else {
            Self::load_from("config.json")
        }
    }

    fn default_home() -> PathBuf {
        dirs::home_dir().expect("Unable to locate home directory")
    }

    pub fn spire_dir(&self) -> PathBuf {
        self.spire_dir
            .as_ref()
            .map(|s| {
                if s.starts_with('~') {
                    let home = Self::default_home();
                    if s == "~" {
                        home
                    } else {
                        home.join(s.strip_prefix("~/").unwrap_or(s.strip_prefix("~").unwrap()))
                    }
                } else {
                    PathBuf::from(s)
                }
            })
            .unwrap_or_else(|| Self::default_home().join(".spire"))
    }

    pub fn db_path(&self) -> PathBuf {
        self.db_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("database.db"))
    }

    pub fn yara_rules_path(&self) -> PathBuf {
        self.yara_rules_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("yara_rules/yara/test"))
    }
}
