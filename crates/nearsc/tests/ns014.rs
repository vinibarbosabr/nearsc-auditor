use std::path::PathBuf;

use nearsc::engine;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn missing_and_false_overflow_checks_flag_exactly_ns014() {
    for name in ["vuln", "false_value"] {
        let result = engine::scan_path(&fixture(&format!("ns014/{name}")));
        assert!(
            result.parse_errors.is_empty(),
            "unexpected parse errors: {:?}",
            result.parse_errors
        );
        let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
        assert_eq!(ids, vec!["NS014"], "{name}: {ids:?}");
    }
}

#[test]
fn pinned_overflow_checks_is_clean() {
    let result = engine::scan_path(&fixture("ns014/fixed"));
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(result.findings.is_empty(), "{:?}", result.findings);
}
