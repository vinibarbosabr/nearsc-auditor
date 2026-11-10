use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns009() {
    let result = engine::scan_path(&fixture("ns009/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS009", "NS009"], "{:?}", result.findings);
    assert_eq!(
        result.findings[0].severity,
        nearsc::finding::Severity::Medium
    );
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
    assert!(result.findings[0].message.contains("draw_winner"));
    assert!(result.findings[1].message.contains("lucky_number"));
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns009/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn bookkeeping_timestamps_are_not_flagged() {
    let result = engine::scan_path(&fixture("ns009/bookkeeping_timestamp.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn example_contract_flags_the_entropy_seed() {
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    let ns009 = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "NS009")
        .expect("NS009 finding");
    assert!(ns009.message.contains("draw_winner"));
}
