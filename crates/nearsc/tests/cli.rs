use std::path::{Path, PathBuf};

use assert_cmd::Command;
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
