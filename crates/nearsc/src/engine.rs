use std::path::{Path, PathBuf};

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
    /// Same-crate guard helpers: names from the crate's guard index
    /// (`assert_*`/`require_*`/... helpers whose bodies perform the caller
    /// check directly or through a chain, per `rules::guard`). Rules credit
    /// a body calling one of these as guarded; see `rules::guard`.
    pub guard_helpers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParseError {
    pub file: String,
    pub message: String,
}

/// Parsed view of one `Cargo.toml` manifest, shared by manifest rules.
pub struct ManifestContext {
    /// Path relative to the scan root, forward slashes.
    pub file: String,
    /// Raw manifest source (rules parse what they need; no execution).
    pub manifest: String,
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
///
/// Files are grouped by crate root (nearest ancestor directory containing a
/// `Cargo.toml`, bounded by the scan root; a single-file scan is its own
/// group) and the guard-helper index is built per crate, so a setter that
/// delegates its caller check to a sibling module of the same crate is
/// credited (the PotLock campaign shape). A single `.rs` file keeps the
/// v0.1 file-scoped semantics. Directory scans also collect every
/// `Cargo.toml` manifest and run the manifest rules over each one.
fn scan_with(
    target: &Path,
    check: impl Fn(&FileContext) -> Vec<Finding>,
) -> (Vec<Finding>, Vec<ParseError>) {
    let mut files = Vec::new();
    let mut manifests = Vec::new();
    if target.is_file() {
        files.push(target.to_path_buf());
    } else {
        for entry in WalkDir::new(target)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| entry.depth() == 0 || !is_skipped_dir(entry))
            .filter_map(|entry| entry.ok())
        {
            if entry.file_type().is_file() {
                let path = entry.path().to_path_buf();
                if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    files.push(path);
                } else if path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
                    manifests.push(path);
                }
            }
        }
    }

    // Group files by crate root. A single-file scan forms one group; a
    // directory scan groups each file under its nearest crate manifest,
    // falling back to the scan root when there is none (fixture dirs).
    let mut groups: Vec<(PathBuf, Vec<PathBuf>)> = Vec::new();
    for file in files {
        let root = if target.is_file() {
            target.to_path_buf()
        } else {
            crate_root(&file, target)
        };
        match groups
            .iter_mut()
            .find(|(group_root, _)| *group_root == root)
        {
            Some((_, group)) => group.push(file),
            None => groups.push((root, vec![file])),
        }
    }

    let mut findings = Vec::new();
    let mut parse_errors = Vec::new();

    for (_, group) in &groups {
        // Parse the whole crate group first, then index, then check: the
        // guard-helper index must see every function of the crate.
        let mut parsed: Vec<(PathBuf, String, syn::File)> = Vec::new();
        for path in group {
            let rel = rel_path(path, target);
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
                Ok(ast) => parsed.push((path.clone(), source, ast)),
                Err(err) => parse_errors.push(ParseError {
                    file: rel,
                    message: err.to_string(),
                }),
            }
        }
        let tables: Vec<crate::rules::guard::FnTable> = parsed
            .iter()
            .flat_map(|(_, _, ast)| crate::rules::guard::fn_tables(ast))
            .collect();
        let index = crate::rules::guard::guard_index(&tables);

        for (path, source, ast) in &parsed {
            let context = FileContext {
                file: rel_path(path, target),
                source: source.clone(),
                ast: ast.clone(),
                abi: crate::abi::AbiIndex::build(ast),
                guard_helpers: index.clone(),
            };
            findings.extend(check(&context));
        }
    }

    // Manifest rules run once per collected `Cargo.toml` (never for
    // single-file `.rs` scans).
    for manifest in &manifests {
        let Ok(source) = std::fs::read_to_string(manifest) else {
            parse_errors.push(ParseError {
                file: rel_path(manifest, target),
                message: "manifest unreadable".to_string(),
            });
            continue;
        };
        let context = ManifestContext {
            file: rel_path(manifest, target),
            manifest: source,
        };
        findings.extend(crate::rules::run_all_manifest(&context));
    }
    (findings, parse_errors)
}

/// Path relative to the scan root, forward slashes, absolute-looking when
/// the file is the scan target itself.
fn rel_path(path: &Path, target: &Path) -> String {
    path.strip_prefix(target)
        .ok()
        .filter(|rel| !rel.as_os_str().is_empty())
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"))
}

/// Nearest ancestor directory of `file` (inclusive) that contains a
/// `Cargo.toml`, bounded by `scan_root`.
fn crate_root(file: &Path, scan_root: &Path) -> PathBuf {
    let mut dir = file.parent().map(Path::to_path_buf);
    while let Some(current) = dir {
        if current.join("Cargo.toml").is_file() {
            return current;
        }
        if current == scan_root {
            break;
        }
        dir = current.parent().map(Path::to_path_buf);
    }
    scan_root.to_path_buf()
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
