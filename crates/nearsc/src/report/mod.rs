//! Output renderers: text, JSON, SARIF. HTML lands in `report/html.rs`.

pub mod sarif;

use crate::engine::ScanResult;
use std::fmt::Write as _;

/// Plain text (terminal) rendering. Byte-stable for the same input.
pub fn render_text(out: &mut String, result: &ScanResult) {
    for finding in &result.findings {
        let _ = writeln!(
            out,
            "{:<8} {} {}:{} {}",
            finding.severity.as_str().to_uppercase(),
            finding.rule_id,
            finding.file,
            finding.line,
            finding.message
        );
    }
    for error in &result.parse_errors {
        let _ = writeln!(out, "parse-error {}: {}", error.file, error.message);
    }
    let summary = &result.summary;
    let _ = writeln!(
        out,
        "{} findings (critical {}, high {}, medium {}, low {}, info {})",
        result.findings.len(),
        summary.critical,
        summary.high,
        summary.medium,
        summary.low,
        summary.info
    );
}

/// Pretty JSON of the scan envelope.
pub fn render_json(result: &ScanResult) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(result)?)
}

/// SARIF 2.1.0 document.
pub fn render_sarif(result: &ScanResult) -> anyhow::Result<String> {
    Ok(sarif::render(result))
}
