use nearsc::engine;

/// A small snippet that triggers NS002 (a `.then` callback without
/// `#[private]`). The promise target is state-like (a fixed literal) so the
/// snippet exercises only NS002, not NS010.
const NS002_VULN: &str = r#"
use near_sdk::Promise;

pub fn call(account: near_sdk::AccountId) -> Promise {
    assert!(ALLOWED.contains(&account));
    Promise::new(account).then(on_result)
}

pub fn on_result() {}

const ALLOWED: [&str; 1] = ["a.near"];
"#;

#[test]
fn walk_prunes_build_and_vcs_dirs() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("target/debug")).expect("mkdir");
    std::fs::create_dir_all(dir.path().join("node_modules/pkg")).expect("mkdir");
    std::fs::create_dir_all(dir.path().join(".git/objects")).expect("mkdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    std::fs::write(dir.path().join("target/debug/vendored.rs"), NS002_VULN).expect("write");
    std::fs::write(dir.path().join("node_modules/pkg/vendored.rs"), NS002_VULN).expect("write");
    std::fs::write(dir.path().join(".git/objects/vendored.rs"), NS002_VULN).expect("write");
    std::fs::write(dir.path().join("src/lib.rs"), NS002_VULN).expect("write");

    let result = engine::scan_path(dir.path());
    assert!(
        result.parse_errors.is_empty(),
        "unexpected parse errors: {:?}",
        result.parse_errors
    );
    let files: Vec<&str> = result.findings.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(files, vec!["src/lib.rs"], "pruned dirs leaked: {files:?}");
}

#[test]
fn explicit_target_dir_is_scanned_even_if_named_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target");
    std::fs::create_dir_all(&target).expect("mkdir");
    std::fs::write(target.join("lib.rs"), NS002_VULN).expect("write");

    let result = engine::scan_path(&target);
    let files: Vec<&str> = result.findings.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(files, vec!["lib.rs"], "{:?}", result.findings);
}
