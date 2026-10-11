use std::{fs, path::Path};

use crate::Config;

pub fn should_monitor_path(path: &Path, config: &Config) -> bool {
    for excluded_path in &config.excluded_paths {
        if path.starts_with(excluded_path) {
            return false;
        }
    }

    if let Some(extension) = path.extension().and_then(|ext| ext.to_str())
        && config
            .excluded_extensions
            .contains(&extension.to_lowercase())
    {
        return false;
    }

    if let Some(file_name) = path.file_name().and_then(|name| name.to_str())
        && config.excluded_files.contains(&file_name.to_string())
    {
        return false;
    }

    true
}

pub fn load_config() -> anyhow::Result<Config> {
    let config_path = match std::env::var_os("SPIRE_AGENT_CONFIG") {
        Some(path) => std::path::PathBuf::from(path),
        None => dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Unable to get config directory"))?
            .join("spire/Config.toml"),
    };
    if std::env::var_os("SPIRE_AGENT_CONFIG").is_some() && !config_path.is_file() {
        anyhow::bail!(
            "Configured agent file is missing: {}",
            config_path.display()
        );
    }

    if !Path::new(&config_path).exists() {
        let config_dir = config_path.parent().unwrap();
        fs::create_dir_all(config_dir)?;

        let default_content = r#"
# Signed feed settings and scan_limits are in config.json (working directory).

# Исключённые пути
excluded_paths = ["/root/.local/share/fish/", "/root/.spire", "/root/.spire/data/", "/root/.local/share/spire_quarantine/"]

# Исключённые расширения файлов
excluded_extensions = ["log", "tmp", "bak", "db"]

# Исключённые имена файлов
excluded_files = ["secret.txt", ".gitignore", "fish_history", ".bash_history"]

excluded_processes = ["firefox", "chrome", "systemd"]

telemetry = true
telemetry_url = "http://127.0.0.1:8080"
enrollment_token = ""
# Detection-only by default. Set "quarantine" to enable response explicitly.
response_policy = "observe"
"#;

        fs::write(&config_path, default_content)?;
    }

    let config_content = fs::read_to_string(&config_path)?;
    let config: Config = toml::from_str(&config_content)?;
    for path in &config.watch_paths {
        anyhow::ensure!(path.is_absolute(), "Watch paths must be absolute");
    }
    Ok(config)
}
