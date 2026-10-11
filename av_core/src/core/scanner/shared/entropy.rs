use std::fs::read;
use std::path::PathBuf;

pub const THRESHOLD: f32 = 7.0;

pub fn calculate_entropy(file_path: PathBuf) -> Result<f64, std::io::Error> {
    let bytes = read(file_path)?;
    if bytes.is_empty() {
        return Ok(0.0);
    }

    let mut frequencies = [0u64; 256];
    for &byte in &bytes {
        frequencies[byte as usize] += 1;
    }

    // Вычисление энтропии
    let total_bytes = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in &frequencies {
        if count > 0 {
            let probability = count as f64 / total_bytes;
            entropy -= probability * probability.log2();
        }
    }

    Ok(entropy)
}
