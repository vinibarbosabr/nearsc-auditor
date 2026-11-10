use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns007() {
    let result = engine::scan_path(&fixture("ns007/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS007", "NS007"], "{:?}", result.findings);
    assert_eq!(
        result.findings[0].severity,
        nearsc::finding::Severity::Medium
    );
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
    assert!(result.findings[0].message.contains("total_pending"));
    assert!(result.findings[1].message.contains("drain_balances"));
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns007/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn loop_over_local_vec_is_not_flagged() {
    let result = engine::scan_path(&fixture("ns007/local_iterator.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn private_callback_loops_are_not_flagged() {
    let result = engine::scan_path(&fixture("ns007/private_callback_exempt.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn example_contract_flags_the_unbounded_seed() {
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    let ns007 = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "NS007")
        .expect("NS007 finding");
    assert!(ns007.message.contains("total_pending"));
}
