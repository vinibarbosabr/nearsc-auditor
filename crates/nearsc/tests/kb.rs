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
fn embedded_index_parses_with_the_shipped_counts() {
    let entries = kb::load_index().expect("embedded index parses");
    let patterns = entries.iter().filter(|e| e.kind == "pattern").count();
    let audits = entries.iter().filter(|e| e.kind == "audit").count();
    let postmortems = entries.iter().filter(|e| e.kind == "postmortem").count();
    // Exact counts: the README and docs/KNOWLEDGE-BASE.md quote these numbers.
    assert_eq!(patterns, 15, "patterns: {patterns}");
    assert_eq!(audits, 7, "audits: {audits}");
    assert_eq!(postmortems, 2, "postmortems: {postmortems}");
    assert_eq!(entries.len(), 24);
}

#[test]
fn pattern_text_serves_full_doc_bodies() {
    let body = kb::pattern_text("callback-privacy").expect("pattern by slug");
    assert!(body.contains("## Vulnerable pattern"), "body: {body}");
    assert!(body.contains("## Fixed pattern"), "body: {body}");
    // Frontmatter is stripped: the body starts at the markdown heading.
    assert!(
        body.starts_with("\n# Callback privacy"),
        "body starts: {body}"
    );
    // Rule-id lookup is the path the MCP patterns tool uses per finding.
    let by_rule = kb::pattern_text("ns002").expect("pattern by rule id");
    assert!(by_rule.contains("## Vulnerable pattern"));
    assert!(kb::pattern_text("NS999").is_none());
}

#[test]
fn embedded_registry_loads_with_the_shipped_entries() {
    let registry = nearsc::rpc::load_registry().expect("embedded registry parses");
    let audits = registry.audits_for("intents.near");
    assert!(!audits.is_empty(), "intents.near must carry audit links");
    assert!(registry.audits_for("unknown-account.near").is_empty());
}

#[test]
fn search_matches_tags_and_titles() {
    let entries = kb::build_index(&kb::repo_data_dir()).expect("building index");
    assert!(!kb::search(&entries, "callback").is_empty());
    assert!(!kb::search(&entries, "storage").is_empty());
}
