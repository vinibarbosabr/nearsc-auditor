use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns008() {
    let result = engine::scan_path(&fixture("ns008/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS008", "NS008"], "{:?}", result.findings);
    assert_eq!(
        result.findings[0].severity,
        nearsc::finding::Severity::Medium
    );
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
    assert!(result.findings[0].message.contains("register_note"));
    assert!(result.findings[1].message.contains("track"));
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns008/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn local_writes_are_not_flagged() {
    let result = engine::scan_path(&fixture("ns008/local_write.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn private_callback_writes_are_not_flagged() {
    let result = engine::scan_path(&fixture("ns008/private_callback_exempt.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn payable_deposit_stays_clean() {
    // deposit() stores under the caller's account but is #[payable]: the
    // storage pathway is paid for at call time. The example must not carry a
    // second NS008 site besides free_note.
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    let ns008: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "NS008")
        .collect();
    assert_eq!(ns008.len(), 1, "NS008 seeds drifted: {ns008:?}");
    assert!(ns008[0].message.contains("free_note"));
}

#[test]
fn example_contract_flags_the_unpaid_seed() {
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    let ns008 = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "NS008")
        .expect("NS008 finding");
    assert!(ns008.message.contains("free_note"), "{:?}", result.findings);
}
