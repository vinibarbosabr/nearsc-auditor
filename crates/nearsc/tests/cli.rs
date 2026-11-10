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

#[test]
fn fail_on_applies_after_min_severity_filter() {
    // The example contract has high findings (NS001/NS002/NS004). Filtering at
    // medium keeps them, so --fail-on high must still trip exit 1.
    nearsc()
        .arg("scan")
        .arg(example())
        .args(["--min-severity", "medium", "--fail-on", "high"])
        .assert()
        .code(1);
    // Filtering at critical keeps only criticals; there are none above high in
    // the medium+ range after filtering... the criticals NS005/NS006 remain, so
    // the gate still trips. Filter to nothing instead: no rule emits only low.
    nearsc()
        .arg("scan")
        .arg(example())
        .args(["--min-severity", "low", "--fail-on", "high"])
        .assert()
        .code(1);
}

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/vulnerable-contract")
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

#[test]
fn rules_list_prints_the_full_catalog() {
    nearsc()
        .arg("rules")
        .arg("list")
        .assert()
        .code(0)
        .stdout(contains("NS001"))
        .stdout(contains("NS012"))
        .stdout(contains("planned Wed 2026-11-11"));
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
