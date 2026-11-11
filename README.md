# nearsc

**Security auditing toolkit for NEAR smart contracts.**

> **Hackathon build in progress (Nov 9–14, 2026).** nearsc v0.1 ships on Nov 14. The v1 prompt stack is preserved under `legacy/`. Design docs live in `docs/`; commands marked "planned" are not shipped yet. Follow the commits on `feat/hackathon`.

nearsc v0.1 will ship three things, all deterministic and offline:

1. `nearsc`, a static scanner for NEAR contract Rust source (CLI, text/JSON/SARIF/HTML output).
2. `nearsc-mcp`, an MCP server that gives coding agents the scanner plus a knowledge base of NEAR audit precedent.
3. A knowledge base of real NEAR vulnerability patterns, audit summaries, and postmortems, embedded in the binary.

Built at NEAR HACKATHON 2026, tracks: security, agents, open.

**Status: engine complete, not yet installable.** All 12 v0.1 rules (NS001-NS012) are shipped with fixture pairs ([docs/RULES.md](docs/RULES.md)). Run `cargo run -p nearsc -- scan examples/vulnerable-contract` for the seeded findings; `--format text|json|sarif|html`, `--only`, `--min-severity`, `--fail-on`, and `--output` are wired; `cargo run -p nearsc -- rules list|show` renders the catalog; `cargo run -p nearsc -- contract wrap.near` fetches on-chain deployment info over public RPC (outside the offline scan path) against the audited-build registry, which ships empty by design ([docs/DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md) D-008). Not shipped yet: crates.io install, the five MCP tools (the server currently exposes an echo spike), `skill/`, `action/`. The final README with verified install steps lands with the v0.1.0 release on Nov 14.

## Repository layout

- `docs/` — design documentation; every doc labels planned vs shipped behavior.
- `legacy/` — the v1 prompt-stack baseline, preserved per hackathon rule Q-003. Tag `pre-hackathon` is the exact baseline state.
- `HACKATHON.md` — the official hackathon rules, kept at the repo root as the primary reference.

## Baseline and hackathon work

Per Q-003/Q-005: the `pre-hackathon` tag marks the v1 prompt-stack baseline (June–July 2026). Everything above it on `feat/hackathon` is new work built during the NEAR Hackathon 2026 window, with AI coding agents (see `docs/` for design decisions). The final README will link the tag diff.

Process: built with agent-assisted audits; findings and their fixes are tracked as issues labeled [audit-finding](https://github.com/vinibarbosabr/nearsc-auditor/issues?q=label%3Aaudit-finding).

## License

MIT. See [LICENSE](LICENSE).
