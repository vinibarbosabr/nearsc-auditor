# nearsc

**Security auditing toolkit for NEAR smart contracts.**

> **Hackathon build in progress (Nov 9–14, 2026).** nearsc v0.1 ships on Nov 14. The v1 prompt stack is preserved under `legacy/`. Design docs live in `docs/`; commands marked "planned" are not shipped yet. Follow the commits on `feat/hackathon`.

nearsc v0.1 will ship three things, all deterministic and offline:

1. `nearsc`, a static scanner for NEAR contract Rust source (CLI, text/JSON/SARIF/HTML output).
2. `nearsc-mcp`, an MCP server that gives coding agents the scanner plus a knowledge base of NEAR audit precedent.
3. A knowledge base of real NEAR vulnerability patterns, audit summaries, and postmortems, embedded in the binary: 15 pattern classes with audit-precedent links, 7 audit entries + 2 postmortems (Potlock/Guvenkaya 2024 and NEAR Intents/Guvenkaya 2025 in the classified per-finding format), and a seeded audited-build registry ([docs/KNOWLEDGE-BASE.md](docs/KNOWLEDGE-BASE.md)).

Built at NEAR HACKATHON 2026, tracks: security, agents, open.

**Status: engine, MCP server, skill, and action shipped; not yet installable from crates.io.** All 12 v0.1 rules (NS001-NS012) are shipped with fixture pairs ([docs/RULES.md](docs/RULES.md)). Run `cargo run -p nearsc -- scan examples/vulnerable-contract` for the seeded findings; `--format text|json|sarif|html`, `--only`, `--min-severity`, `--fail-on`, and `--output` are wired; `cargo run -p nearsc -- rules list|show` renders the catalog; `cargo run -p nearsc -- contract wrap.near` fetches on-chain deployment info over public RPC (outside the offline scan path) against the audited-build registry, which is seeded from shipped audit entries with honest coverage caveats ([docs/DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md) D-008, [docs/KNOWLEDGE-BASE.md](docs/KNOWLEDGE-BASE.md)). The five MCP tools are live ([docs/MCP.md](docs/MCP.md)), the agent skill ships at [`skill/SKILL.md`](skill/SKILL.md), and the GitHub Action at [`action/`](action) dogfoods itself in CI with SARIF upload. The KB (15 pattern classes, 7 audit entries, 2 postmortems) and the audited-build registry ship embedded in the binary (D-005). Not shipped yet: crates.io install (lands with `v0.1.0` on Nov 14).

## Use as an MCP server

```bash
cargo install nearsc-mcp   # after the v0.1.0 release; today: build from this checkout
```

opencode (`opencode.json` in the project you want audited):

```json
{ "mcp": { "nearsc": { "type": "local", "command": ["cargo", "run", "--quiet", "-p", "nearsc-mcp"], "enabled": true } } }
```

Claude Code:

```bash
claude mcp add nearsc -- nearsc-mcp
```

Five read-only tools: `nearsc_scan`, `nearsc_patterns`, `nearsc_audits`, `nearsc_contract_info`, `nearsc_poc_scaffold`. Path-taking tools are confined to the project the harness opened. Full contract: [docs/MCP.md](docs/MCP.md). Safety model: [docs/SECURITY.md](docs/SECURITY.md).

## Use as an agent skill

Point your harness at [`skill/SKILL.md`](skill/SKILL.md) (opencode/Claude-compatible frontmatter). It carries the audit workflow: Recon → Scan → Verify → Report, NEAR context, and the safety rules.

## GitHub Action

```yaml
- uses: vinibarbosabr/nearsc-auditor/action@v0.1.0
  with:
    path: ./contracts
    fail-on: high
```

Uploads nothing by itself; pair it with `github/codeql-action/upload-sarif` using the `sarif` output (see [.github/workflows/self-scan.yml](.github/workflows/self-scan.yml) for a full example).

## Repository layout

- `docs/` — design documentation; every doc labels planned vs shipped behavior.
- `skill/` — the agent skill (v2 workflow for NEAR contract audits).
- `action/` — the composite GitHub Action (dogfooded by `.github/workflows/self-scan.yml`).
- `legacy/` — the v1 prompt-stack baseline, preserved per hackathon rule Q-003. Tag `pre-hackathon` is the exact baseline state.
- `HACKATHON.md` — the official hackathon rules, kept at the repo root as the primary reference.

## Baseline and hackathon work

Per Q-003/Q-005: the `pre-hackathon` tag marks the v1 prompt-stack baseline (June–July 2026). Everything above it on `feat/hackathon` is new work built during the NEAR Hackathon 2026 window, with AI coding agents (see `docs/` for design decisions). The final README will link the tag diff.

Process: built with agent-assisted audits; findings and their fixes are tracked as issues labeled [audit-finding](https://github.com/vinibarbosabr/nearsc-auditor/issues?q=label%3Aaudit-finding).

## License

MIT. See [LICENSE](LICENSE).
