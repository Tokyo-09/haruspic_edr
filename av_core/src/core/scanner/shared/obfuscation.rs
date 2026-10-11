use crate::types::FileData;

pub fn detect_xor_obfuscation(data: &FileData) -> Option<String> {
    let non_ascii_count = data.bytes.iter().filter(|&&b| !b.is_ascii()).count();
    let total = data.bytes.len();

    if total == 0 {
        return None;
    }

    let ratio = non_ascii_count as f64 / total as f64;

    if ratio > 0.7 {
        return Some("Probably encrypted".to_string());
    }

    None
}
