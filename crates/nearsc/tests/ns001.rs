use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns001() {
    let result = engine::scan_path(&fixture("ns001/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS001"]);
    assert!(result.findings[0].message.contains("ft_transfer"));
    assert_eq!(result.findings[0].severity, nearsc::finding::Severity::High);
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Spec
    );
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns001/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn helper_with_the_check_satisfies_the_rule() {
    let result = engine::scan_path(&fixture("ns001/helper_fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn zero_yocto_check_is_not_a_guard() {
    let result = engine::scan_path(&fixture("ns001/zero_yocto.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS001"]);
}

#[test]
fn macro_one_yocto_check_recognized() {
    let result = engine::scan_path(&fixture("ns001/macro_check.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn if_shaped_one_yocto_check_is_recognized() {
    let result = engine::scan_path(&fixture("ns001/if_guard.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn delegation_to_standards_token_counts_as_guarded() {
    // The NEP-141 thin-wrapper shape: the check lives inside the delegated
    // near-contract-standards `FungibleToken` impl, reached through
    // `self.<field>.ft_transfer(...)`. The wrapper is not a missing check.
    let result = engine::scan_path(&fixture("ns001/delegated_transfer.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn delegation_to_internal_helper_without_check_stays_flagged() {
    // Negative control: `self.<field>.<method>()` credit applies only to
    // the standards-delegation shapes; delegating to an internal helper
    // without any check keeps the NS001 finding.
    let result = engine::scan_path(&fixture("ns001/delegated_transfer_unguarded.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS001"], "{:?}", result.findings);
}

#[test]
fn example_contract_flags_unchecked_transfer() {
    let result = engine::scan_path(&fixture("../../examples/vulnerable-contract"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ns001 = result
        .findings
        .iter()
        .find(|finding| finding.rule_id == "NS001")
        .expect("NS001 finding");
    assert!(ns001.message.contains("ft_transfer"));
}
