use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn nearsc() -> Command {
    Command::cargo_bin("nearsc").expect("nearsc binary")
}

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/vulnerable-contract")
}

#[test]
fn scan_missing_path_fails_loudly() {
    nearsc()
        .args(["scan", "/definitely/not/here"])
        .assert()
        .code(2)
        .stderr(contains("scan target not found"));
}

#[test]
fn scan_real_file_succeeds_and_reports_ns002() {
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .assert()
        .code(0)
        .stdout(contains("NS002"));
}

#[test]
fn fail_on_trips_exit_1() {
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--fail-on", "high"])
        .assert()
        .code(1)
        .stdout(contains("NS002"));
}

#[test]
fn fail_on_below_threshold_exits_0() {
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--fail-on", "critical"])
        .assert()
        .code(0)
        .stdout(contains("NS002"));
}

#[test]
fn bad_format_exits_2() {
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--format", "yaml"])
        .assert()
        .code(2);
}

#[test]
fn min_severity_filters_lower_findings() {
    // The ns002 fixture's only finding is high; filtering at critical hides it.
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--min-severity", "critical"])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("NS002").not());
}

#[test]
fn min_severity_at_threshold_keeps_findings() {
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--min-severity", "high"])
        .assert()
        .code(0)
        .stdout(contains("NS002"));
}

/// The example contract keeps high findings at --min-severity medium,
/// so --fail-on high still trips exit 1.
#[test]
fn fail_on_trips_after_min_severity_filter_keeps_highs() {
    nearsc()
        .arg("scan")
        .arg(example())
        .args(["--min-severity", "medium", "--fail-on", "high"])
        .assert()
        .code(1);
}

/// Criticals survive a medium filter too, so a critical gate still trips.
#[test]
fn fail_on_trips_on_criticals_kept_by_filter() {
    nearsc()
        .arg("scan")
        .arg(example())
        .args(["--min-severity", "low", "--fail-on", "critical"])
        .assert()
        .code(1);
}

/// Filtering away the only finding disarms the gate: exit 0.
/// The ns002 fixture's single high finding is removed by a critical filter,
/// so --fail-on high must NOT trip.
#[test]
fn fail_on_is_disarmed_when_filter_removes_the_trigger() {
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--min-severity", "critical", "--fail-on", "high"])
        .assert()
        .code(0);
}

#[test]
fn output_writes_file_and_keeps_stdout_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("report.txt");
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .arg("--output")
        .arg(&out)
        .assert()
        .code(0)
        .stdout(predicates::str::is_empty());
    let content = std::fs::read_to_string(&out).expect("report file");
    assert!(content.contains("NS002"), "report missing NS002: {content}");
}

#[test]
fn output_json_writes_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("report.json");
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--format", "json", "--output"])
        .arg(&out)
        .assert()
        .code(0)
        .stdout(predicates::str::is_empty());
    let content = std::fs::read_to_string(&out).expect("report file");
    assert!(content.contains("\"rule_id\": \"NS002\""));
}

/// HTML reports: untrusted snippets are escaped and markup never leaks.
#[test]
fn html_report_escapes_untrusted_snippets() {
    // Answer the escaping question directly: a hand-written ScanResult with a
    // hostile snippet renders escaped (through report::html::render).
    let scan = nearsc::engine::ScanResult {
        tool: "nearsc",
        version: "0.1.0",
        target: "<script>alert(1)</script>".to_string(),
        findings: vec![nearsc::finding::Finding {
            rule_id: "NS002",
            title: "x",
            severity: nearsc::finding::Severity::High,
            confidence: nearsc::finding::Confidence::Spec,
            file: "a<b.rs".to_string(),
            line: 3,
            column: 5,
            snippet: "<script>alert(1)</script>".to_string(),
            message: "payload & \"quotes\" 'single' <em>markup</em>".to_string(),
            refs: &["https://example.com/"],
        }],
        parse_errors: vec![],
        summary: nearsc::engine::Summary {
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
        },
    };
    let content = nearsc::report::html::render(&scan);
    assert!(
        !content.contains("<script>alert"),
        "unescaped markup leaked into the report"
    );
    assert!(content.contains("&lt;script&gt;"), "{content}");
    assert!(content.contains("&quot;"));
    assert!(content.contains("&#39;"));
    assert!(content.contains("&lt;b.rs"));
}

/// The full report shape: summary cards, findings with refs, the footer
/// disclaimer, and no JavaScript.
#[test]
fn html_report_is_self_contained() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/vulnerable-contract");
    let out_file = tempfile::tempdir().expect("tempdir");
    let out = out_file.path().join("report.html");
    nearsc()
        .arg("scan")
        .arg(&example)
        .args(["--format", "html", "--output"])
        .arg(&out)
        .assert()
        .code(0);
    let content = std::fs::read_to_string(&out).expect("html file");
    assert!(content.starts_with("<!DOCTYPE html>"));
    assert!(
        !content.contains("<script"),
        "html report ships no javascript"
    );
    for severity in [
        "severity-critical",
        "severity-high",
        "severity-medium",
        "severity-low",
    ] {
        assert!(content.contains(severity), "missing {severity}");
    }
    assert!(content.contains("NS001") && content.contains("NS012"));
    assert!(
        content.contains("Static analysis output") && content.contains("not a substitute"),
        "the disclaimer must be present"
    );
    assert_eq!(content.matches("<article").count(), 12);
}

/// SARIF writes through --output as a file too.
#[test]
fn output_sarif_writes_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("report.sarif");
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--format", "sarif", "--output"])
        .arg(&out)
        .assert()
        .code(0)
        .stdout(predicates::str::is_empty());
    let content = std::fs::read_to_string(&out).expect("sarif file");
    let doc: serde_json::Value = serde_json::from_str(&content).expect("sarif parses");
    assert_eq!(doc["version"], "2.1.0");
}

#[test]
fn rules_list_prints_the_full_catalog() {
    nearsc()
        .arg("rules")
        .arg("list")
        .assert()
        .code(0)
        .stdout(contains("NS001"))
        .stdout(contains("NS012"))
        .stdout(contains("shipped"));
}

#[test]
fn rules_list_json_prints_the_catalog() {
    nearsc()
        .args(["rules", "list", "--format", "json"])
        .assert()
        .code(0)
        .stdout(contains("\"id\": \"NS001\""))
        .stdout(contains("\"status\": \"shipped\""));
}

#[test]
fn scan_only_runs_exactly_the_requested_rule() {
    // The ns001 fixture triggers NS001; running with --only ns002 emits nothing.
    nearsc()
        .arg("scan")
        .arg(fixture("ns001/vuln.rs"))
        .args(["--only", "ns002"])
        .assert()
        .code(0)
        .stdout(contains("0 findings"))
        .stdout(contains("NS001").not());
    // Running with --only ns001 emits exactly NS001.
    nearsc()
        .arg("scan")
        .arg(fixture("ns001/vuln.rs"))
        .args(["--only", "ns001"])
        .assert()
        .code(0)
        .stdout(contains("NS001"));
}

#[test]
fn scan_only_unknown_id_exits_2() {
    nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--only", "NOPE"])
        .assert()
        .code(2)
        .stderr(contains("unknown rule id"));
}

#[test]
fn rules_show_prints_entry_and_unknown_id_fails() {
    nearsc()
        .args(["rules", "show", "NS002"])
        .assert()
        .code(0)
        .stdout(contains("callback-not-private"));
    nearsc()
        .args(["rules", "show", "NOPE"])
        .assert()
        .code(2)
        .stderr(contains("unknown rule id"));
}

/// SARIF output parses and its shape matches plan section 5: driver rules,
/// one result per finding, level mapping, relative artifact uri.
#[test]
fn sarif_output_is_valid_sarif_2_1_0() {
    let stdout = nearsc()
        .arg("scan")
        .arg(fixture("ns002/vuln.rs"))
        .args(["--format", "sarif"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let doc: serde_json::Value = serde_json::from_slice(&stdout).expect("sarif is valid json");
    assert_eq!(
        doc["$schema"],
        "https://json.schemastore.org/sarif-2.1.0.json"
    );
    assert_eq!(doc["version"], "2.1.0");
    let run = &doc["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "nearsc");
    assert!(
        run["tool"]["driver"]["rules"]
            .as_array()
            .expect("driver rules")
            .iter()
            .any(|rule| rule["id"] == "NS002"),
        "driver rules carry the catalog"
    );
    let result = &run["results"][0];
    assert_eq!(result["ruleId"], "NS002");
    assert_eq!(result["level"], "error", "critical/high map to error");
    assert!(
        result["message"]["text"].is_string(),
        "message text present"
    );
    let location = &result["locations"][0]["physicalLocation"];
    assert!(
        location["artifactLocation"]["uri"]
            .as_str()
            .expect("uri")
            .ends_with("vuln.rs"),
        "artifact uri is the relative path"
    );
    assert_eq!(location["region"]["startLine"], 13);
}

/// Medium findings report as "warning"; low/info as "note" (plan section 4).
#[test]
fn sarif_level_mapping_covers_all_severities() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/vulnerable-contract");
    let stdout = nearsc()
        .arg("scan")
        .arg(&example)
        .args(["--format", "sarif"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let doc: serde_json::Value = serde_json::from_slice(&stdout).expect("sarif is valid json");
    let results = doc["runs"][0]["results"].as_array().expect("results array");
    let levels: Vec<&str> = results.iter().filter_map(|r| r["level"].as_str()).collect();
    assert!(levels.contains(&"error"), "criticals are errors");
    assert!(levels.contains(&"warning"), "mediums are warnings");
    assert!(levels.contains(&"note"), "lows are notes");
    assert_eq!(results.len(), 12, "one result per finding");
}
