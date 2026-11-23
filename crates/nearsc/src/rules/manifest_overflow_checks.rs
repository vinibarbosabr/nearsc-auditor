//! NS014: `[profile.release]` without `overflow-checks = true`.
//!
//! rustc's release profile defaults to `overflow-checks = false`: release
//! arithmetic wraps silently. A NEAR contract built from a crate manifest
//! that does not pin `overflow-checks = true` ships wrapping math in its
//! production binary (the Potlock GUV-5 class: "No Runtime Overflow Checks
//! Applied").
//!
//! v0.2 scope (heuristic): the engine collects every `Cargo.toml` manifest
//! under the scan root; this rule reports any manifest whose
//! `[profile.release]` is missing or whose `overflow-checks` is not exactly
//! `true`. A workspace member inheriting the pin from the workspace root
//! still reports: the inheritance is invisible to the scanner, and an
//! unpinned member manifest is exactly where the pin gets lost when a crate
//! is built standalone (measured on the sputnik-dao-contract workspace:
//! root pinned, four member manifests unpinned, four findings).

use super::ManifestRule;
use crate::engine::ManifestContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct ManifestOverflowChecks;

const RULE_ID: &str = "NS014";
const TITLE: &str = "Release profile without overflow-checks";
const REFS: &[&str] = &["https://doc.rust-lang.org/cargo/reference/profiles.html"];

impl ManifestRule for ManifestOverflowChecks {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn check(&self, context: &ManifestContext) -> Vec<Finding> {
        let Ok(table) = context.manifest.parse::<toml::Table>() else {
            // Unparseable manifests are engine parse errors, not findings.
            return Vec::new();
        };
        let (line, ok) = match table.get("profile").and_then(|p| p.get("release")) {
            None => (1usize, false),
            Some(release) => {
                let line = release_line(context);
                match release.get("overflow-checks").and_then(|v| v.as_bool()) {
                    Some(true) => (line, true),
                    _ => (line, false),
                }
            }
        };
        if ok {
            return Vec::new();
        }
        vec![Finding {
            rule_id: RULE_ID,
            title: TITLE,
            severity: Severity::Medium,
            confidence: Confidence::Heuristic,
            file: context.file.clone(),
            line,
            column: 1,
            snippet: first_line(&context.manifest),
            message: "release profile does not pin overflow-checks = true; release arithmetic wraps silently (set [profile.release] overflow-checks = true or use checked math)".to_string(),
            refs: REFS,
        }]
    }
}

/// Best-effort line of the `[profile.release]` table in the source text.
fn release_line(context: &ManifestContext) -> usize {
    for (index, source_line) in context.manifest.lines().enumerate() {
        let trimmed = source_line.trim();
        if trimmed.starts_with("[profile.release]") {
            return index + 1;
        }
    }
    1
}

fn first_line(manifest: &str) -> String {
    manifest.lines().next().unwrap_or_default().to_string()
}
