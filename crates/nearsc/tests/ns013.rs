use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns013() {
    // The S-1 / issue #239 shape: storage_withdraw pays the recorded
    // available balance without decrementing it.
    let result = engine::scan_path(&fixture("ns013/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS013"]);
    assert_eq!(result.findings[0].severity, nearsc::finding::Severity::High);
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
    assert!(result.findings[0].message.contains("storage_withdraw"));
}

#[test]
fn fixed_fixture_emits_nothing() {
    // The payout draws down the recorded balance in the same method.
    let result = engine::scan_path(&fixture("ns013/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn view_and_refund_shapes_stay_out() {
    // Balance views and deposit refunds are not payout endpoints: no
    // finding (no over-triggering on ordinary storage-management code).
    let result = engine::scan_path(&fixture("ns013/view_no_finding.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}
