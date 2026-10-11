use serde_json::{Value, json};
use std::fs;

const MAX_PROCESSES: usize = 250;

pub fn process_snapshot() -> Value {
    #[allow(unused_mut)]
    let mut processes: Vec<Value> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if processes.len() >= MAX_PROCESSES {
                    break;
                }
                let name = entry.file_name();
                let pid = match name.to_string_lossy().parse::<i64>() {
                    Ok(pid) => pid,
                    Err(_) => continue,
                };
                let base = entry.path();
                let comm = fs::read_to_string(base.join("comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let cmdline = fs::read_to_string(base.join("cmdline"))
                    .unwrap_or_default()
                    .replace('\0', " ")
                    .trim()
                    .to_string();
                let exe = fs::read_link(base.join("exe"))
                    .ok()
                    .map(|p| p.display().to_string());
                let ppid = parse_ppid(&base.join("stat"));
                processes.push(json!({
                    "pid": pid,
                    "ppid": ppid,
                    "name": comm,
                    "exe": exe,
                    "cmdline": cmdline,
                }));
            }
        }
    }

    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": crate::telemetry::hostname(),
        "process_count": processes.len(),
        "truncated": processes.len() >= MAX_PROCESSES,
        "processes": processes,
    })
}

#[cfg(target_os = "linux")]
fn parse_ppid(stat_path: &std::path::Path) -> Option<i64> {
    let raw = fs::read_to_string(stat_path).ok()?;
    // /proc/<pid>/stat: pid (comm) state ppid ...
    let close = raw.rfind(')')?;
    let rest = raw.get(close + 2..)?;
    rest.split_whitespace().nth(1)?.parse().ok()
}
