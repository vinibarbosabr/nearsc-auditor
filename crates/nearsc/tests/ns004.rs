use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns004() {
    let result = engine::scan_path(&fixture("ns004/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS004"]);
    assert!(result.findings[0].message.contains("on_payout"));
    assert_eq!(result.findings[0].severity, nearsc::finding::Severity::High);
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns004/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn example_contract_flags_unchecked_promise_result() {
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ns004 = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "NS004")
        .expect("NS004 finding");
    assert!(ns004.message.contains("on_deposit_result"));
}
