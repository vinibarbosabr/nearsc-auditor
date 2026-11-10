use std::path::PathBuf;

use nearsc::engine;

/// The example contract is the demo + dogfood surface: its scan output is
/// contractual. Every seed must fire exactly its own rule; nothing else.
/// When a new rule seed lands in `examples/vulnerable-contract`, its id is
/// appended to the expected vector in the same commit.
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
        vec!["NS001", "NS002", "NS003", "NS004", "NS005", "NS006", "NS007", "NS008", "NS012"],
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
