//! Contract tests for the `nearsc-mcp` stdio server.
//!
//! Speaks raw JSON-RPC to the spawned binary (the same newline-delimited
//! frames a harness uses), so the protocol surface itself is the oracle:
//! tool names, schemas, confinement, and finding shapes. Offline by
//! default; the RPC test runs only when `NearSC_MCP_NET_TESTS=1`.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};

/// Spawn the server with the repo root as its working directory, exactly like
/// a harness session opened in the project would.
fn spawn_server() -> (Child, mpsc::Receiver<String>) {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    let mut child = Command::new(env!("CARGO_BIN_EXE_nearsc-mcp"))
        .current_dir(&repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nearsc-mcp");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    (child, rx)
}

/// One JSON-RPC request, returning the response with the matching id.
/// Panics with the last server line on a 30s stall so CI cannot hang.
fn call(child: &mut Child, rx: &mpsc::Receiver<String>, request: Value) -> Value {
    let id = request["id"].as_i64().expect("request id");
    let stdin = child.stdin.as_mut().expect("stdin");
    writeln!(stdin, "{request}").expect("write request");
    stdin.flush().expect("flush");

    let deadline = Duration::from_secs(30);
    loop {
        let line = rx
            .recv_timeout(deadline)
            .unwrap_or_else(|_| panic!("server stalled waiting for response to id {id}"));
        let message: Value = serde_json::from_str(&line)
            .unwrap_or_else(|err| panic!("bad JSON line: {line}: {err}"));
        if message.get("id").and_then(Value::as_i64) == Some(id) {
            return message;
        }
        // Notifications and other ids are skipped; the channel keeps them ordered.
    }
}

fn initialized(child: &mut Child, rx: &mpsc::Receiver<String>) {
    let response = call(
        child,
        rx,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "contract-test", "version": "0"}
            }
        }),
    );
    assert!(
        response.get("result").is_some(),
        "initialize failed: {response}"
    );
    let stdin = child.stdin.as_mut().expect("stdin");
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .expect("notify");
    stdin.flush().expect("flush");
}

/// `tools/call` returning the parsed inner payload.
fn call_tool(
    child: &mut Child,
    rx: &mpsc::Receiver<String>,
    id: i64,
    name: &str,
    args: Value,
) -> Value {
    let response = call(
        child,
        rx,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        }),
    );
    if let Some(error) = response.get("error") {
        panic!("{name} returned an MCP error: {error}");
    }
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} returned no text content: {response}"));
    serde_json::from_str(text).unwrap_or_else(|err| panic!("{name} payload is not JSON: {err}"))
}

/// `tools/call` expecting a structured MCP error; returns the error message.
fn call_tool_error(
    child: &mut Child,
    rx: &mpsc::Receiver<String>,
    id: i64,
    name: &str,
    args: Value,
) -> String {
    let response = call(
        child,
        rx,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        }),
    );
    response["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} was expected to error, got: {response}"))
        .to_string()
}

const FIXTURE: &str = "tests/fixtures/ns002/vuln.rs";

#[test]
fn server_speaks_mcp_and_lists_exactly_the_five_tools() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);

    let response = call(
        &mut child,
        &rx,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let tools: Vec<&str> = response["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(
        tools,
        vec![
            "nearsc_audits",
            "nearsc_contract_info",
            "nearsc_patterns",
            "nearsc_poc_scaffold",
            "nearsc_scan"
        ]
    );
    child.kill().expect("kill server");
}

#[test]
fn scan_finds_exactly_ns002_on_the_fixture() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let envelope = call_tool(&mut child, &rx, 3, "nearsc_scan", json!({"path": FIXTURE}));
    let findings = envelope["findings"].as_array().expect("findings");
    assert_eq!(
        findings.len(),
        1,
        "fixture must emit exactly one finding: {envelope}"
    );
    assert_eq!(findings[0]["rule_id"], "NS002");
    assert_eq!(findings[0]["severity"], "high");
    assert_eq!(envelope["summary"]["high"], 1);
    child.kill().expect("kill server");
}

#[test]
fn scan_min_severity_filters_the_envelope() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let envelope = call_tool(
        &mut child,
        &rx,
        4,
        "nearsc_scan",
        json!({"path": "examples/vulnerable-contract", "min_severity": "high"}),
    );
    let counts = envelope["summary"].as_object().expect("summary");
    assert_eq!(counts["critical"], 2);
    assert_eq!(counts["high"], 4);
    assert_eq!(
        counts["medium"], 0,
        "min_severity=high must drop medium: {counts:?}"
    );
    assert_eq!(counts["low"], 0);
    child.kill().expect("kill server");
}

#[test]
fn scan_rejects_paths_outside_the_working_directory() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let message = call_tool_error(&mut child, &rx, 5, "nearsc_scan", json!({"path": "/etc"}));
    assert!(
        message.contains("escapes the working directory"),
        "unexpected error: {message}"
    );
    let message = call_tool_error(
        &mut child,
        &rx,
        6,
        "nearsc_scan",
        json!({"path": "../outside"}),
    );
    assert!(
        message.contains("scan target not found"),
        "unexpected error: {message}"
    );
    child.kill().expect("kill server");
}

#[test]
fn patterns_return_the_full_doc_for_a_rule_id() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let payload = call_tool(
        &mut child,
        &rx,
        7,
        "nearsc_patterns",
        json!({"query": "NS002"}),
    );
    let hits = payload.as_array().expect("patterns array");
    assert!(
        !hits.is_empty(),
        "NS002 must match at least the callback pattern"
    );
    let hit = hits
        .iter()
        .find(|hit| hit["rule"] == "NS002")
        .expect("callback-privacy hit");
    assert_eq!(hit["id"], "callback-privacy");
    let body = hit["body"].as_str().expect("body");
    assert!(body.contains("## Vulnerable pattern"), "body: {body}");
    assert!(body.contains("## Fixed pattern"), "body: {body}");
    child.kill().expect("kill server");
}

#[test]
fn audits_return_index_entries_with_sources() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let payload = call_tool(
        &mut child,
        &rx,
        8,
        "nearsc_audits",
        json!({"query": "callback"}),
    );
    let entries = payload.as_array().expect("audits array");
    assert!(
        !entries.is_empty(),
        "callback must match at least one precedent"
    );
    for entry in entries {
        assert!(!entry["source"].as_str().unwrap_or_default().is_empty());
        assert!(!entry["confidence"].as_str().unwrap_or_default().is_empty());
        assert_ne!(entry["kind"], "pattern");
    }
    child.kill().expect("kill server");
}

#[test]
fn poc_scaffold_returns_skeleton_files_without_writing() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let payload = call_tool(
        &mut child,
        &rx,
        9,
        "nearsc_poc_scaffold",
        json!({"rule_id": "ns002", "contract_path": FIXTURE}),
    );
    assert_eq!(payload["rule"], "NS002");
    let files = payload["files"].as_object().expect("files map");
    assert!(
        files
            .keys()
            .any(|path| path.ends_with("tests/poc_ns002.rs")),
        "files: {:?}",
        files.keys().collect::<Vec<_>>()
    );
    let instructions = payload["instructions"].as_str().expect("instructions");
    assert!(instructions.contains("Never deploy or sign on mainnet"));
    child.kill().expect("kill server");
}

#[test]
fn poc_scaffold_rejects_unknown_rule_ids() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let message = call_tool_error(
        &mut child,
        &rx,
        10,
        "nearsc_poc_scaffold",
        json!({"rule_id": "NS999", "contract_path": FIXTURE}),
    );
    assert!(
        message.contains("unknown rule id"),
        "unexpected error: {message}"
    );
    child.kill().expect("kill server");
}

#[test]
fn contract_info_validates_the_account_id_before_any_network_call() {
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let message = call_tool_error(
        &mut child,
        &rx,
        11,
        "nearsc_contract_info",
        json!({"account_id": "WRAP.NEAR"}),
    );
    assert!(
        message.contains("invalid account id"),
        "unexpected error: {message}"
    );
    let message = call_tool_error(
        &mut child,
        &rx,
        12,
        "nearsc_contract_info",
        json!({"account_id": "wrap..near"}),
    );
    assert!(
        message.contains("invalid account id"),
        "unexpected error: {message}"
    );
    child.kill().expect("kill server");
}

/// Live mainnet lookup: opt-in so CI stays offline-deterministic.
#[test]
fn contract_info_fetches_a_live_account() {
    if std::env::var("NearSC_MCP_NET_TESTS").as_deref() != Ok("1") {
        return;
    }
    let (mut child, rx) = spawn_server();
    initialized(&mut child, &rx);
    let payload = call_tool(
        &mut child,
        &rx,
        13,
        "nearsc_contract_info",
        json!({"account_id": "wrap.near"}),
    );
    assert_eq!(payload["account_id"], "wrap.near");
    assert_eq!(payload["exists"], true);
    assert_eq!(payload["has_code"], true);
    assert!(payload["fetched_at"]
        .as_str()
        .is_some_and(|stamp| !stamp.is_empty()));
    child.kill().expect("kill server");
}
