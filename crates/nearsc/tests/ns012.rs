use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn vulnerable_fixture_emits_exactly_ns012() {
    let result = engine::scan_path(&fixture("ns012/vuln.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS012"]);
    assert!(result.findings[0].message.contains("set_fee"));
    assert_eq!(
        result.findings[0].severity,
        nearsc::finding::Severity::Medium
    );
    assert_eq!(
        result.findings[0].confidence,
        nearsc::finding::Confidence::Heuristic
    );
}

#[test]
fn fixed_fixture_emits_nothing() {
    let result = engine::scan_path(&fixture("ns012/fixed.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn manual_guard_satisfies_the_rule() {
    let result = engine::scan_path(&fixture("ns012/manual_guard.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn internal_and_non_near_impl_setters_are_not_flagged() {
    // ABI gate: internal helpers and non-`#[near]` impls are not
    // attacker-callable, so setter-named shapes there are not NS012
    // findings (the sputnikdao2 `Policy::update_*` shape).
    let result = engine::scan_path(&fixture("ns012/not_exported.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn owner_field_guard_satisfies_the_rule() {
    // The guard shape the NS012 message recommends: predecessor compared
    // against contract state (the owner field).
    let result = engine::scan_path(&fixture("ns012/owner_guard.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn owner_getter_guard_satisfies_the_rule() {
    // The factory-2 shape: the predecessor is compared against
    // `self.get_owner()`, a method call, instead of the `self.owner` field.
    // Same guard, different spelling.
    let result = engine::scan_path(&fixture("ns012/owner_getter_guard.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn delegated_owner_guard_helper_satisfies_the_rule() {
    // The sputnikdao-factory2 shape: the setter calls a same-file
    // `assert_owner()` helper that performs the predecessor-vs-owner check.
    // The helper's own body carries the guard.
    let result = engine::scan_path(&fixture("ns012/delegated_owner_guard.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}

#[test]
fn non_guard_helper_caller_stays_flagged() {
    // A `self.assert_*()` call is credited only when the same-file helper
    // actually performs a caller check; otherwise the setter stays a
    // finding (no over-crediting).
    let result = engine::scan_path(&fixture("ns012/delegated_helper_not_guard.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS012"], "unguarded setter must stay flagged: {ids:?}");
}

#[test]
fn state_write_body_defers_to_ns006() {
    let result = engine::scan_path(&fixture("ns012/defers_to_ns006.rs"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert_eq!(ids, vec!["NS006"], "NS012 must defer to NS006: {ids:?}");
}
