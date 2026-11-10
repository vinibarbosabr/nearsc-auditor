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
