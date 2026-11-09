use nearsc::kb;

#[test]
fn index_json_is_in_sync_with_data_directory() {
    let data_dir = kb::repo_data_dir();
    let generated = kb::build_index(&data_dir).expect("building index");
    let index_path = data_dir.join("index.json");
    let checked_in: Vec<kb::IndexEntry> = serde_json::from_str(
        &std::fs::read_to_string(&index_path).expect("data/index.json must exist"),
    )
    .expect("data/index.json must be valid JSON");

    assert_eq!(
        checked_in, generated,
        "data/index.json is stale; regenerate with `cargo run -p nearsc -- kb-index`"
    );
}

#[test]
fn index_covers_the_kb_floor() {
    let entries = kb::build_index(&kb::repo_data_dir()).expect("building index");
    let patterns = entries.iter().filter(|e| e.kind == "pattern").count();
    let audits = entries.iter().filter(|e| e.kind == "audit").count();
    let postmortems = entries.iter().filter(|e| e.kind == "postmortem").count();
    assert!(patterns >= 12, "patterns: {patterns}");
    assert!(audits >= 3, "audits: {audits}");
    assert!(postmortems >= 1, "postmortems: {postmortems}");
}

#[test]
fn search_matches_tags_and_titles() {
    let entries = kb::build_index(&kb::repo_data_dir()).expect("building index");
    assert!(!kb::search(&entries, "callback").is_empty());
    assert!(!kb::search(&entries, "storage").is_empty());
}
