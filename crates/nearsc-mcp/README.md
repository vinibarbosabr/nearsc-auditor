# nearsc-mcp

**MCP server exposing the nearsc NEAR contract scanner to coding agents.**

`nearsc-mcp` serves five read-only tools over stdio (Model Context Protocol):
scanning a project for NEAR contract vulnerabilities, looking up vulnerability
patterns, searching real audit/postmortem precedent, checking a contract's
on-chain deployment info against an audited-build registry, and scaffolding a
workspaces-rs proof-of-concept test. The scan path and the knowledge base are
embedded in the binary (no data directory, no network); only
`nearsc_contract_info` uses the network, and path-taking tools are confined to
the project the harness opened.

Part of the [nearsc-auditor](https://github.com/vinibarbosabr/nearsc-auditor)
toolkit; uses the same engine as the
[`nearsc`](https://crates.io/crates/nearsc) CLI.

## Install

```bash
cargo install nearsc-mcp
```

## Configure

Claude Code:

```bash
claude mcp add nearsc -- nearsc-mcp
```

Generic stdio shape (opencode, Cursor, Claude Desktop; check your harness docs):

```json
{
  "mcpServers": {
    "nearsc": { "command": "nearsc-mcp", "args": [] }
  }
}
```

## Tools

- `nearsc_scan {path, min_severity?}` - scan a directory or file.
- `nearsc_patterns {query, severity?}` - vulnerability pattern lookup by keyword, rule id, or tag.
- `nearsc_audits {query, project?}` - real audit and postmortem precedent.
- `nearsc_contract_info {account_id, network?}` - on-chain deployment info + audited-build registry match.
- `nearsc_poc_scaffold {rule_id, contract_path}` - workspaces-rs PoC test skeleton.

Safety model: read-only, paths confined to the working directory, account-id
validation before any request, scanned code treated as data (never executed).
Full contract:
[MCP.md](https://github.com/vinibarbosabr/nearsc-auditor/blob/main/docs/MCP.md).

## License

MIT. See [LICENSE](https://github.com/vinibarbosabr/nearsc-auditor/blob/main/LICENSE).
