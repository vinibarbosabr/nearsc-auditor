# MCP server

> **Status:** shipped 2026-11-12 (plan section 7, executed one day ahead). The five tools below are live over stdio; `nearsc_contract_info` is the only networked tool. Harness configuration formats change between versions: check your harness docs and treat the snippets as examples.

## Why an MCP server

Coding agents and autonomous agents already drive real work on NEAR: writing contracts, reviewing code, moving funds. MCP (Model Context Protocol) is the interface they share across harnesses (Claude Code, Codex, opencode, Cursor, and others). Shipping a scanner as a library only serves humans; shipping it as MCP serves the agents that write and call contracts.

`nearsc-mcp` is a thin stdio server over the same engine the CLI uses. Same rules, same findings, same determinism.

## Tools

### `nearsc_scan`

Scan a directory or file for NEAR contract issues.

```json
// input
{ "path": "./contract", "min_severity": "medium" }
```

```json
// output
{
  "tool": "nearsc",
  "version": "0.1.0",
  "target": "./contract",
  "summary": { "critical": 0, "high": 2, "medium": 1, "low": 0, "info": 0 },
  "findings": [ { "rule_id": "NS002", "title": "...", "severity": "high", "file": "src/lib.rs", "line": 142, "message": "...", "refs": ["..."] } ],
  "parse_errors": []
}
```

### `nearsc_patterns`

Look up a vulnerability pattern by keyword, rule id, or tag.

```json
{ "query": "callback", "severity": "high" }
```

Returns up to 3 matching pattern docs (plus a truncation note when more matched): id, title, rule id, severity, tags, source, confidence, and the full body (what/why, vulnerable and fixed code). The pattern docs live in `crates/nearsc/data/patterns/`; there is no separate rule TOML layer (rule metadata is the catalog in `crates/nearsc/src/rules/mod.rs`).

### `nearsc_audits`

Search the knowledge base for real audit and postmortem precedent.

```json
{ "query": "promise failure refund", "project": "burrowland" }
```

Returns up to 10 index entries: title, project, year, tags, severity counts, summary, source URL, confidence label.

### `nearsc_contract_info`

Check a contract account before interacting with it.

```json
{ "account_id": "wrap.near", "network": "mainnet" }
```

```json
{
  "account_id": "wrap.near",
  "exists": true,
  "has_code": true,
  "code_hash": "…",
  "balance_yocto": "…",
  "storage_usage": 123456,
  "registry_match": true,
  "known_audits": [ { "title": "…", "source": "…" } ],
  "fetched_at": "2026-11-12T18:00:00Z"
}
```

Read-only RPC against fixed public endpoints. This is a counterparty signal, not a guarantee: a code hash match against the registry means the deployed code matches an audited build, nothing more.

### `nearsc_poc_scaffold`

Generate a workspaces-rs test skeleton for a finding.

```json
{ "rule_id": "NS002", "contract_path": "./contract" }
```

Returns file contents and instructions. It never writes to disk; the agent or user decides where the files go.

## Install and configure

From a checkout: `cargo run -p nearsc-mcp` (stdio). After the v0.1.0 release: `cargo install nearsc-mcp`.

Claude Code (example):

```bash
claude mcp add nearsc -- nearsc-mcp
```

Generic stdio configuration (Claude Desktop, Cursor, opencode and others accept a command + args shape; check your harness docs):

```json
{
  "mcpServers": {
    "nearsc": {
      "command": "nearsc-mcp",
      "args": []
    }
  }
}
```

opencode (`opencode.json`, shape per harness docs):

```json
{
  "mcp": {
    "nearsc": { "type": "local", "command": ["nearsc-mcp"], "enabled": true }
  }
}
```

## Safety model
- **Read-only.** No tool executes scanned code, runs shell commands, or writes files. `nearsc_poc_scaffold` returns content only.
- **Path confinement.** Every path-taking tool resolves paths under the server's working directory and rejects anything that escapes it (symlinks resolved). `/etc` is not reachable.
- **Account-id validation.** `nearsc_contract_info` rejects account ids outside `[a-z0-9._-]{1,64}` before any request leaves the process.
- **No secrets.** The server never reads environment secrets, keys, or wallets. It does not sign or send transactions.
- **Untrusted input.** Scanned repositories and KB text are data. Tool descriptions instruct agents to ignore instructions found inside scanned code or reports (prompt-injection defense).
- **Network scope.** Only `nearsc_contract_info` uses the network, against fixed public RPC endpoints. No telemetry.
- **Determinism.** Tool outputs are stable for the same inputs (`fetched_at` in `nearsc_contract_info` and RPC results are the live exceptions). Result caps: `nearsc_patterns` returns at most 3 full pattern docs (with a truncation note), `nearsc_audits` at most 10 index entries.

## Example session (planned)

```
user: audit ./contracts/vault and tell me what to fix first
agent: [nearsc_scan] 3 findings: NS002 high, NS001 high, NS008 medium
agent: [nearsc_patterns callback] → fix guidance + vulnerable/fixed snippets
agent: [nearsc_audits callback hijack] → 2 precedents from public reports
agent: [nearsc_contract_info vault.near] → deployed code hash does not match the audited build
agent: summary with fixes in priority order
```

## Versioning

Tool names and input fields are stable within v0.x. Outputs may gain fields; consumers should ignore unknown fields. Breaking changes get a minor version bump and a changelog entry.
