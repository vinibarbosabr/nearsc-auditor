use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns005() {
    let result = engine::scan_path(&fixture("ns005/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS005"]);
    assert!(result.findings[0].message.contains("migrate"));
    assert_eq!(
        result.findings[0].severity,
        nearsc::finding::Severity::Critical
    );
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns005/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn plain_init_is_not_flagged() {
    let source = "#[init]\npub fn new(owner: near_sdk::AccountId) -> Self { Self { owner } }";
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("plain_init.rs");
    std::fs::write(&path, source).expect("write fixture");
    let result = engine::scan_path(&path);
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn example_contract_flags_unguarded_migrate() {
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ns005 = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "NS005")
        .expect("NS005 finding");
    assert!(ns005.message.contains("migrate"));
}
