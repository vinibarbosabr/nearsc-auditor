use std::path::Path;

use serde::Serialize;

use crate::finding::{Finding, Severity};
use crate::rules;

/// Parsed view of one Rust source file shared by all rules.
pub struct FileContext {
    /// Path relative to the scan root, using forward slashes.
    pub file: String,
    pub source: String,
    pub ast: syn::File,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParseError {
    pub file: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Result of one scan, shaped like the public JSON envelope (plan section 5.1).
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub tool: &'static str,
    pub version: &'static str,
    pub target: String,
    pub findings: Vec<Finding>,
    pub parse_errors: Vec<ParseError>,
    pub summary: Summary,
}

/// Scan a directory tree, or a single `.rs` file.
pub fn scan_path(target: &Path) -> ScanResult {
    let mut files = Vec::new();
    if target.is_file() {
        files.push(target.to_path_buf());
    } else {
        for entry in walkdir::WalkDir::new(target)
            .sort_by_file_name()
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|ext| ext.to_str()) == Some("rs")
            {
                files.push(entry.path().to_path_buf());
            }
        }
    }

    let mut findings = Vec::new();
    let mut parse_errors = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(target)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let source = match std::fs::read_to_string(path) {
            Ok(source) => source,
            Err(err) => {
                parse_errors.push(ParseError {
                    file: rel,
                    message: err.to_string(),
                });
                continue;
            }
        };
        match syn::parse_file(&source) {
            Ok(ast) => {
                let context = FileContext {
                    file: rel,
                    source,
                    ast,
                };
                findings.extend(rules::run_all(&context));
            }
            Err(err) => parse_errors.push(ParseError {
                file: rel,
                message: err.to_string(),
            }),
        }
    }

    // Stable ordering: file, line, then rule id.
    findings.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.rule_id).cmp(&(b.file.as_str(), b.line, b.rule_id))
    });

    let summary = Summary {
        critical: count(findings.iter(), Severity::Critical),
        high: count(findings.iter(), Severity::High),
        medium: count(findings.iter(), Severity::Medium),
        low: count(findings.iter(), Severity::Low),
        info: count(findings.iter(), Severity::Info),
    };

    ScanResult {
        tool: "nearsc",
        version: env!("CARGO_PKG_VERSION"),
        target: target.display().to_string(),
        findings,
        parse_errors,
        summary,
    }
}

fn count<'a>(findings: impl Iterator<Item = &'a Finding>, severity: Severity) -> usize {
    findings
        .filter(|finding| finding.severity == severity)
        .count()
}
