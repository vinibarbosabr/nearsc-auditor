//! RPC lookups: the only networked part of nearsc (the `contract` subcommand).
//!
//! The scan path stays offline and deterministic; this module is reached from
//! the CLI's public-RPC query only, so contract counterparty data (existence,
//! balance, deployment code hash) can be fetched and compared with
//! `data/registry.json`. Registration/DAO-D-008 decision: the registry ships
//! empty; entries are seeded from the audit KB, never invented.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Public RPC endpoints (NEAR docs provider list, mainfest-first order).
pub const MAINNET_RPC: &str = "https://rpc.mainnet.near.org";
pub const TESTNET_RPC: &str = "https://rpc.testnet.near.org";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn endpoint(self) -> &'static str {
        match self {
            Network::Mainnet => MAINNET_RPC,
            Network::Testnet => TESTNET_RPC,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

/// The contract counterparty report the CLI prints.
#[derive(Debug, Serialize)]
pub struct ContractInfo {
    pub account_id: String,
    pub network: &'static str,
    pub exists: bool,
    pub has_code: bool,
    pub code_hash: Option<String>,
    pub balance_yocto: Option<String>,
    pub storage_usage: Option<u64>,
    /// None when no registry entry exists for this account.
    pub registry_match: Option<bool>,
    /// Audit links from the matching registry entry.
    pub known_audits: Vec<RegistryAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAudit {
    pub title: String,
    pub source: String,
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: &'a str,
    method: &'static str,
    params: QueryParams<'a>,
}

#[derive(Serialize)]
struct QueryParams<'a> {
    request_type: &'static str,
    account_id: &'a str,
    finality: &'static str,
}
#[derive(Debug, Deserialize)]
struct RpcError {
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    result: Option<QueryResult>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
pub struct QueryResult {
    amount: Option<String>,
    storage_usage: Option<u64>,
    /// Base58 SHA-256 of the deployed contract code; the all-ones hash marks
    /// "no contract deployed".
    code_hash: Option<String>,
}

impl QueryResult {
    pub fn amount(&self) -> Option<&str> {
        self.amount.as_deref()
    }

    pub fn storage_usage(&self) -> Option<u64> {
        self.storage_usage
    }

    pub fn code_hash(&self) -> Option<&str> {
        self.code_hash.as_deref()
    }
}

/// The empty-contract sentinel hash (sha256 of empty bytes, base58).
const NO_CODE_HASH: &str = "11111111111111111111111111111111";

/// Registry contents: well-known accounts, their audit-backed code hashes,
/// and verification dates. Empty-by-design at v0.1 (see docs/DESIGN-DECISIONS.md).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Registry {
    #[serde(flatten)]
    entries: std::collections::BTreeMap<String, RegistryEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub label: String,
    pub code_hash: String,
    pub audits: Vec<RegistryAudit>,
    pub verified_at: String,
}

/// Load `data/registry.json`; an absent file is an empty registry, not an
/// error (the lookup then simply never matches).
pub fn load_registry() -> anyhow::Result<Registry> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/registry.json");
    if !path.exists() {
        return Ok(Registry::default());
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Does the live code hash match the audited hash recorded for this account?
/// `Ok(None)` = unregistered account; no claim either way.
pub fn registry_match(registry: &Registry, account_id: &str, code_hash: &str) -> Option<bool> {
    let entry = registry.entries.get(account_id)?;
    Some(entry.code_hash == code_hash)
}

impl Registry {
    pub fn audits_for(&self, account_id: &str) -> Vec<RegistryAudit> {
        self.entries
            .get(account_id)
            .map(|entry| entry.audits.clone())
            .unwrap_or_default()
    }
}

/// Parse a `query` response envelope into the domain fields. Pure function;
/// unit-tested with fixture payloads (no network in tests).
pub fn parse_query_response(body: &str) -> anyhow::Result<Option<QueryResult>> {
    // The node's missing-account shape hides the UNKNOWN_ACCOUNT detail in
    // the raw `data`/`cause` fields, so scan the whole envelope text before
    // treating an error as fatal.
    let account_missing = body.contains("UNKNOWN_ACCOUNT")
        || body.contains("does not exist")
        || body.contains("unknown account");
    let envelope: RpcEnvelope = serde_json::from_str(body).context("parsing RPC response body")?;
    if envelope.error.is_some() {
        if account_missing {
            return Ok(None);
        }
        let message = envelope
            .error
            .and_then(|error| error.message)
            .unwrap_or_default();
        anyhow::bail!("RPC error: {message}");
    }
    Ok(envelope.result)
}

/// Fetch the contract counterparty data over public RPC. The request shape
/// (JSON-RPC query, finality final) is fixed; no user data beyond the
/// account id leaves the process.
pub fn fetch_contract_info(account_id: &str, network: Network) -> anyhow::Result<ContractInfo> {
    let request: String = serde_json::to_string(&RpcRequest {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "query",
        params: QueryParams {
            request_type: "view_account",
            account_id,
            finality: "final",
        },
    })
    .context("serializing RPC request")?;

    let response = {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        agent
            .post(network.endpoint())
            .set("Content-Type", "application/json")
            .send_string(&request)
            .context("network request to the public RPC failed")?
    };
    let body = response.into_string().context("reading RPC response")?;
    let result = parse_query_response(&body)?;
    let Some(result) = result else {
        return Ok(ContractInfo {
            account_id: account_id.to_string(),
            network: network.as_str(),
            exists: false,
            has_code: false,
            code_hash: None,
            balance_yocto: None,
            storage_usage: None,
            registry_match: None,
            known_audits: vec![],
        });
    };

    let code_hash = result.code_hash.clone();
    let has_code = code_hash
        .as_deref()
        .is_some_and(|hash| hash != NO_CODE_HASH);
    let registry = load_registry()?;
    let match_result = code_hash
        .as_deref()
        .and_then(|hash| registry_match(&registry, account_id, hash));
    let known_audits = registry.audits_for(account_id);

    Ok(ContractInfo {
        account_id: account_id.to_string(),
        network: network.as_str(),
        exists: true,
        has_code,
        code_hash,
        balance_yocto: result.amount,
        storage_usage: result.storage_usage,
        registry_match: match_result,
        known_audits,
    })
}
