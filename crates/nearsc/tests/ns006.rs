use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns006() {
    let result = engine::scan_path(&fixture("ns006/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS006"]);
    assert!(result.findings[0].message.contains("force_upgrade"));
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
    let result = engine::scan_path(&fixture("ns006/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn internal_and_non_near_impl_helpers_are_not_flagged() {
    // ABI gate: an attacker cannot reach internal helpers, so their
    // state-write shape is not an NS006 finding (v0.2 call graph will
    // route these to their exported wrappers).
    let result = engine::scan_path(&fixture("ns006/not_exported.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn deposit_funded_state_writes_are_not_flagged() {
    // The store_blob shape: the caller prepays the exact storage cost of
    // the write, so the direct state write is contract-managed storage,
    // not a takeover primitive.
    let result = engine::scan_path(&fixture("ns006/prepaid_state_write.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn example_contract_flags_unguarded_state_write() {
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ns006 = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "NS006")
        .expect("NS006 finding");
    assert!(ns006.message.contains("set_state"));
}
