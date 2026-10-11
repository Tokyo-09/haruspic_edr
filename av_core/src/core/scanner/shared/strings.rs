use crate::types::FileData;

pub fn scan_suspicious_strings(data: &FileData) -> Option<String> {
    let suspicious_patterns = [
        "cmd.exe /c",
        "powershell -enc",
        "powershell -nop -c",
        "rm -rf /",
        "wget http://",
        "curl http://",
        "base64 -d",
        "exec ",
        "system(",
        "eval(",
        "shell_exec(",
        "CreateRemoteThread",
        "VirtualAlloc",
        "WriteProcessMemory",
        "RegSetValueEx",
        "/etc/passwd",
        "/root/.ssh/",
        "id_rsa",
    ];

    for s in &data.strings {
        for pattern in &suspicious_patterns {
            if s.contains(pattern) {
                return Some(format!("Detected suspicious string: '{}'", pattern));
            }
        }
    }

    None
}
