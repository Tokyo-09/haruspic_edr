use chrono::{DateTime, Utc};
use std::fs::write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use av_core::core::models::ScanResult;

pub fn generate_html_report(
    results: &[ScanResult],
    output_path: &PathBuf,
    timestamp: Option<u64>,
) -> anyhow::Result<()> {
    let mut html = String::from(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Malware Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #333; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .threat { background-color: #ffdddd; color: #d00; }
                .clean { background-color: #ddffdd; }
                .error { background-color: #ffffdd; color: #d00; }
            </style>
        </head>
        <body>
            <h1>Malware Scan Report</h1>
            <p>Generated on: "#,
    );

    let timestamp_secs = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    if timestamp_secs > 0 {
        let datetime =
            DateTime::<Utc>::from(UNIX_EPOCH + std::time::Duration::from_secs(timestamp_secs));
        let cest_offset = chrono::FixedOffset::east_opt(2 * 3600).expect("Invalid timezone offset");
        let datetime_cest = datetime.with_timezone(&cest_offset);
        html.push_str(&datetime_cest.format("%Y-%m-%d %H:%M:%S %Z").to_string());
    } else {
        html.push_str("Unknown");
    }
    html.push_str("</p>");

    let total = results.len();
    let threats = results
        .iter()
        .filter(|r| matches!(r, ScanResult::Threat { .. } | ScanResult::YaraThreat { .. }))
        .count();
    let errors = results
        .iter()
        .filter(|r| matches!(r, ScanResult::Error { .. }))
        .count();
    html.push_str(&format!(
        "<p>Total files scanned: {total}<br>Threats detected: {threats}<br>Errors: {errors}</p>"
    ));

    html.push_str(
        r#"
        <table>
            <tr>
                <th>File Path</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
        "#,
    );

    for result in results {
        match result {
            ScanResult::Clean(path) => {
                html.push_str(&format!(
                    r#"<tr class="clean">
                        <td>{}</td>
                        <td>Clean</td>
                        <td>-</td>
                    </tr>"#,
                    path.display()
                ));
            }
            ScanResult::Threat { path, malware, .. } => {
                html.push_str(&format!(
                    r#"<tr class="threat">
                        <td>{}</td>
                        <td>Threat</td>
                        <td>{} (MD5: {}, SHA256: {})</td>
                    </tr>"#,
                    path.display(),
                    malware.name,
                    malware.md5hash,
                    malware.sha256hash
                ));
            }
            ScanResult::YaraThreat {
                path,
                matching_rules,
                ..
            } => {
                html.push_str(&format!(
                    r#"<tr class="threat">
                        <td>{}</td>
                        <td>Threat</td>
                        <td>YARA matches: {}</td>
                    </tr>"#,
                    path.display(),
                    matching_rules.join(", ")
                ));
            }
            ScanResult::Error { path, error } => {
                html.push_str(&format!(
                    r#"<tr class="error">
                        <td>{}</td>
                        <td>Error</td>
                        <td>{}</td>
                    </tr>"#,
                    path.display(),
                    error
                ));
            }
        }
    }

    html.push_str(
        r#"
            </table>
        </body>
        </html>
        "#,
    );

    write(output_path, html)?;
    Ok(())
}

#[allow(unused_variables, dead_code)]
pub fn generate_json_report(
    results: &[ScanResult],
    output_path: &Path,
    timestamp: Option<u64>,
) -> anyhow::Result<()> {
    unimplemented!();
}
