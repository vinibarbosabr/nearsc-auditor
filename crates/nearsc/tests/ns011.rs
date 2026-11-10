use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns011() {
    let result = engine::scan_path(&fixture("ns011/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS011"], "{:?}", result.findings);
    assert_eq!(result.findings[0].severity, nearsc::finding::Severity::Low);
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
    assert!(result.findings[0].message.contains("register"));
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns011/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn non_payable_functions_are_not_flagged() {
    let result = engine::scan_path(&fixture("ns011/not_payable.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn payable_deposit_with_abort_and_no_refund_flags() {
    // The example's deposit() is #[payable], has no abort, and stores the
    // value directly: no NS011 finding there.
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    let ns011: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "NS011")
        .collect();
    assert_eq!(ns011.len(), 1, "{:?}", result.findings);
    assert!(ns011[0].message.contains("claim"));
}
