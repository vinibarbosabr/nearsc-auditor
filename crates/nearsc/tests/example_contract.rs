use std::path::PathBuf;

use nearsc::engine;

/// The example contracts are the demo + dogfood surface: the vulnerable
/// contract's scan output is contractual (one finding per seeded rule),
/// and the fixed twin must scan clean. When a new rule seed lands in
/// `examples/vulnerable-contract`, its id is appended to the expected
/// vector in the same commit, and the corresponding fix lands in
/// `examples/fixed-contract`.
#[test]
fn example_contract_emits_exactly_the_seeded_rules() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/vulnerable-contract");
    let result = engine::scan_path(&path);
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );

    let mut ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "NS001", "NS002", "NS003", "NS004", "NS005", "NS006", "NS007", "NS008", "NS009",
            "NS010", "NS011", "NS012",
        ],
        "example contract seeds drifted: {ids:?}"
    );

    // One seed per rule class: exactly one finding per id.
    for id in ids.iter() {
        assert_eq!(
            result.findings.iter().filter(|f| f.rule_id == *id).count(),
            1,
            "expected exactly one {id} seed"
        );
    }
}

/// The patched twin: same surface, every seed fixed. Scans clean; this is
/// the vulnerable-vs-fixed demo oracle.
#[test]
fn fixed_contract_emits_no_findings() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/fixed-contract");
    let result = engine::scan_path(&path);
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    assert!(
        result.findings.is_empty(),
        "fixed contract must scan clean: {:#?}",
        result.findings
    );
}
