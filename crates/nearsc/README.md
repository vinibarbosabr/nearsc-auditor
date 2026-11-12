# nearsc

**Deterministic security scanner for NEAR smart contracts.**

`nearsc` parses NEAR contract Rust source with `syn` and matches it against 13
NEAR-specific vulnerability rules (callback privacy, 1-yocto authorization,
unguarded init/upgrade paths, storage griefing, insecure randomness,
deposit-refund gaps, balance drains, and more).
No network, no LLM, no code execution in the scan path; the same input produces
byte-stable output on any machine.

Findings carry `spec` or `heuristic` confidence labels: every text scan prints
how many are heuristic review hints, and `--min-confidence spec` shows only
findings grounded in documented NEAR semantics. Measured against the audited
`sputnik-dao-contract` snapshot, the rule set went from 29 findings at v0.1.0 to
2 at v0.1.2 without losing a true positive: one real drain the baseline missed
(NS013, the issue #239 class) and one deliberately kept review hint.

Part of the [nearsc-auditor](https://github.com/vinibarbosabr/nearsc-auditor)
toolkit: the CLI scanner, an MCP server for coding agents
([`nearsc-mcp`](https://crates.io/crates/nearsc-mcp)), and an embedded knowledge
base of real NEAR audit precedent.

## Install

```bash
cargo install nearsc
```

## Usage

```bash
# Scan a directory (text output by default)
nearsc scan path/to/contract

# Machine-readable reports
nearsc scan path/to/contract --format json
nearsc scan path/to/contract --format sarif
nearsc scan path/to/contract --format html --output report.html

# CI gate: exit 1 when a critical or high finding is present
nearsc scan path/to/contract --fail-on high

# Rule catalog
nearsc rules list
nearsc rules show NS002

# On-chain deployment info over public RPC (the only networked command)
nearsc contract wrap.near
```

## Documentation

- [Rules catalog](https://github.com/vinibarbosabr/nearsc-auditor/blob/main/docs/RULES.md)
- [Architecture](https://github.com/vinibarbosabr/nearsc-auditor/blob/main/docs/ARCHITECTURE.md)
- [Security model and limits](https://github.com/vinibarbosabr/nearsc-auditor/blob/main/docs/SECURITY.md)

## License

MIT. See [LICENSE](https://github.com/vinibarbosabr/nearsc-auditor/blob/main/LICENSE).
