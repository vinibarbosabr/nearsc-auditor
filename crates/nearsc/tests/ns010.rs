use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns010() {
    let result = engine::scan_path(&fixture("ns010/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS010", "NS010"], "{:?}", result.findings);
    assert_eq!(result.findings[0].severity, nearsc::finding::Severity::High);
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
    assert!(result.findings[0].message.contains("payout"));
    assert!(result.findings[1].message.contains("forward"));
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns010/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn state_derived_targets_are_not_flagged() {
    let result = engine::scan_path(&fixture("ns010/state_derived_target.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn callback_recorded_predecessor_refund_is_not_flagged() {
    // The factory `on_create` shape: a `#[private]` callback refunding the
    // predecessor the contract itself recorded in the initiating call. The
    // parameter is the recorded predecessor, not a caller-chosen target.
    let result = engine::scan_path(&fixture("ns010/callback_refund_path.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn callback_with_arbitrary_param_stays_flagged() {
    // Negative control: a callback parameter that does not carry the
    // recorded-predecessor name keeps the NS010 finding (no over-exemption).
    let result = engine::scan_path(&fixture("ns010/callback_arbitrary_param.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS010"], "{:?}", result.findings);
}

#[test]
fn example_contract_flags_exactly_one_promise_target() {
    // notify_receiver is the NS010 seed; withdraw was reconciled to a
    // state-derived target so the example carries exactly one finding.
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    let ns010: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "NS010")
        .collect();
    assert_eq!(ns010.len(), 1, "{:?}", result.findings);
    assert!(ns010[0].message.contains("notify_receiver"));
}
