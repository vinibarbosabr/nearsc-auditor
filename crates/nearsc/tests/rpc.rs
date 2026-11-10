use nearsc::rpc;

/// A view_account envelope for an existing contract account (fixture shape
/// from the NEAR RPC docs).
const CONTRACT_RESPONSE: &str = r#"{
  "jsonrpc": "2.0",
  "result": {
    "amount": "190000000000000000000000",
    "storage_usage": 123456,
    "code_hash": "Bq6CeRjkG6DSuNDQoUHUa3ShZRySBNhzjuifo6kTfgPi"
  }
}"#;

/// Viewing a non-existent account returns an error mentioning the account.
const MISSING_RESPONSE: &str = r#"{
  "jsonrpc": "2.0",
  "error": {
    "name": "UNKNOWN_ACCOUNT",
    "code": -32000,
    "message": "account missing.near does not exist while viewing"
  }
}"#;

#[test]
fn contract_response_parses_fully() {
    let result = rpc::parse_query_response(CONTRACT_RESPONSE).expect("parses");
    let result = result.expect("account exists");
    assert_eq!(
        result.code_hash(),
        Some("Bq6CeRjkG6DSuNDQoUHUa3ShZRySBNhzjuifo6kTfgPi")
    );
    assert_eq!(result.amount(), Some("190000000000000000000000"));
    assert_eq!(result.storage_usage(), Some(123456));
}

#[test]
fn missing_account_maps_to_none() {
    let result = rpc::parse_query_response(MISSING_RESPONSE).expect("parses");
    assert!(
        result.is_none(),
        "unknown account yields None, not an error"
    );
}

/// The live node's missing-account shape: the UNKNOWN_ACCOUNT detail lives
/// in the raw `data` field, while `message` is a generic "Server error".
const NODE_MISSING_RESPONSE: &str = r#"{
  "jsonrpc": "2.0",
  "error": {
    "name": "HANDLER_ERROR",
    "cause": { "info": { "requested_account_id": "missing.near" }, "name": "UNKNOWN_ACCOUNT" },
    "code": -32000,
    "message": "Server error",
    "data": "account missing.near does not exist while viewing"
  }
}"#;

#[test]
fn node_missing_account_shape_maps_to_none() {
    let result = rpc::parse_query_response(NODE_MISSING_RESPONSE).expect("parses");
    assert!(
        result.is_none(),
        "UNKNOWN_ACCOUNT detail in data: {result:?}"
    );
}

#[test]
fn garbage_response_is_an_error() {
    assert!(rpc::parse_query_response("not json").is_err());
}

/// Registry matching is a pure comparison with a documented None for
/// unregistered accounts.
#[test]
fn registry_match_semantics() {
    let registry: rpc::Registry = serde_json::from_str(
        r#"{ "wrap.near": {
            "label": "Wrapped NEAR",
            "code_hash": "Bq6CeRjkG6DSuNDQoUHUa3ShZRySBNhzjuifo6kTfgPi",
            "audits": [{ "title": "example", "source": "https://example.com" }],
            "verified_at": "2026-11-11"
        } }"#,
    )
    .expect("registry parses");
    assert_eq!(
        rpc::registry_match(
            &registry,
            "wrap.near",
            "Bq6CeRjkG6DSuNDQoUHUa3ShZRySBNhzjuifo6kTfgPi"
        ),
        Some(true)
    );
    assert_eq!(
        rpc::registry_match(&registry, "wrap.near", "different-hash"),
        Some(false)
    );
    assert_eq!(rpc::registry_match(&registry, "unknown.near", "x"), None);
    assert_eq!(registry.audits_for("unknown.near").len(), 0);
    assert_eq!(registry.audits_for("wrap.near").len(), 1);
}

/// The shipped registry is the documented empty placeholder for now; any
/// entry must carry label, audits, and verification date once seeded.
#[test]
fn shipped_registry_parses() {
    let registry = rpc::load_registry().expect("registry file parses");
    assert!(
        registry.audits_for("wrap.near").is_empty(),
        "registry seeds land with the audit KB pass, not before"
    );
}
