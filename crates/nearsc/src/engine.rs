use std::path::Path;

use serde::Serialize;
use walkdir::{DirEntry, WalkDir};

use crate::finding::{Finding, Severity};
use crate::rules;

/// Directory names never scanned: build artifacts, VCS state, dependencies.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

fn is_skipped_dir(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    entry.file_type().is_dir() && SKIP_DIRS.contains(&name.as_ref())
}

/// Parsed view of one Rust source file shared by all rules.
pub struct FileContext {
    /// Path relative to the scan root, using forward slashes.
    pub file: String,
    pub source: String,
    pub ast: syn::File,
    /// Which `fn`s in this file are on the contract's callable surface
    /// (`pub` methods of `#[near]` impl blocks and raw `#[no_mangle]`
    /// exports). Rules that report "any account can call this" only report
    /// exported functions; internal helpers are v0.2 call-graph targets.
    pub abi: crate::abi::AbiIndex,
    /// Same-file helpers whose bodies satisfy the manual guard probe
    /// (`assert_owner()`-style authorization checks). Rules credit a body
    /// calling one of these as guarded; see `rules::body_has_guard_with`.
    pub guard_helpers: Vec<String>,
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

impl Summary {
    /// Recount from a (possibly filtered) findings list so the summary always
    /// matches what is reported.
    pub fn recount(&mut self, findings: &[crate::finding::Finding]) {
        self.critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        self.high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        self.medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        self.low = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        self.info = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();
    }
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
    let (findings, parse_errors) = scan_with(target, |context| rules::run_all(context).to_vec());
    assemble(target, findings, parse_errors)
}

/// Keep findings at or above `min` (critical = most severe) and recount the
/// summary. Shared by the CLI `--min-severity` and the MCP `nearsc_scan`.
pub fn filter_min_severity(result: &mut ScanResult, min: Severity) {
    result.findings.retain(|finding| finding.severity <= min);
    result.summary.recount(&result.findings);
}

/// Scan a directory tree or single `.rs` file, running only the rules whose
/// ids (case-insensitive) appear in `only`.
///
/// TODO: untested as a library entry point; exercised through the CLI tests
/// (`scan --only`) until a consumer needs it directly.
pub fn scan_path_only(target: &Path, only: &[String]) -> ScanResult {
    let requested: Vec<String> = only.iter().map(|id| id.to_ascii_uppercase()).collect();
    let selected: Vec<&'static dyn rules::Rule> = rules::rules()
        .iter()
        .copied()
        .filter(|rule| requested.iter().any(|id| *id == rule.id()))
        .collect();
    let (findings, parse_errors) = scan_with(target, |context| {
        selected
            .iter()
            .flat_map(|rule| rule.check(context))
            .collect()
    });
    assemble(target, findings, parse_errors)
}

/// Walk `target` and run `check` over every parsed file. Shared walker for
/// `scan_path` and `scan_path_only`; returns unsorted findings plus parse
/// errors.
fn scan_with(
    target: &Path,
    check: impl Fn(&FileContext) -> Vec<Finding>,
) -> (Vec<Finding>, Vec<ParseError>) {
    let mut files = Vec::new();
    if target.is_file() {
        files.push(target.to_path_buf());
    } else {
        for entry in WalkDir::new(target)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| entry.depth() == 0 || !is_skipped_dir(entry))
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
            .ok()
            .filter(|rel| !rel.as_os_str().is_empty())
            .map(|rel| rel.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"));
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
                let abi = crate::abi::AbiIndex::build(&ast);
                let guard_helpers = rules::guard_helper_names(&ast);
                let context = FileContext {
                    file: rel,
                    source,
                    ast,
                    abi,
                    guard_helpers,
                };
                findings.extend(check(&context));
            }
            Err(err) => parse_errors.push(ParseError {
                file: rel,
                message: err.to_string(),
            }),
        }
    }
    (findings, parse_errors)
}

fn assemble(
    target: &Path,
    mut findings: Vec<Finding>,
    parse_errors: Vec<ParseError>,
) -> ScanResult {
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
