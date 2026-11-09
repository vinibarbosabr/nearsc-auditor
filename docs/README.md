# nearsc docs

> **Status:** design documentation for nearsc v0.1, built during the NEAR Hackathon 2026 (Nov 1–14). Commands and behaviors marked **planned** are not shipped until the `v0.1.0` tag. If this page and the code disagree, the code wins; open an issue.

nearsc is a security auditing toolkit for NEAR smart contracts: a deterministic scanner, an agent-facing MCP server, and a knowledge base of real NEAR audit precedent.

## Read by audience

| I am a… | Start here |
| --- | --- |
| Judge or first-time visitor | [VISION.md](VISION.md), then [DEMO.md](DEMO.md) |
| Builder scanning a contract | [DEMO.md](DEMO.md), then [RULES.md](RULES.md) |
| Agent / MCP user | [MCP.md](MCP.md), then [SECURITY.md](SECURITY.md) |
| Security researcher | [RULES.md](RULES.md), then [KNOWLEDGE-BASE.md](KNOWLEDGE-BASE.md) |
| Contributor | [CONTRIBUTING.md](CONTRIBUTING.md), then [ARCHITECTURE.md](ARCHITECTURE.md) |
| Comparing tools | [COMPARISON.md](COMPARISON.md) |

## Index

| Doc | Answers |
| --- | --- |
| [VISION.md](VISION.md) | What problem, for whom, why now, what it is not |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the engine, MCP server, and KB fit together |
| [RULES.md](RULES.md) | The 12 rules: what, why, detection, false positives, **status per rule** |
| [MCP.md](MCP.md) | Tool contracts, install per harness, safety model |
| [KNOWLEDGE-BASE.md](KNOWLEDGE-BASE.md) | KB schema, sourcing rules, confidence labels |
| [SECURITY.md](SECURITY.md) | Threat model of the tool itself and its limits |
| [ROADMAP.md](ROADMAP.md) | v0.2 → v0.4 direction |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Add a rule, add a KB entry, dev setup |
| [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) | Public ADRs for the choices that shaped v0.1 |
| [COMPARISON.md](COMPARISON.md) | Prior art and where nearsc fits |
| [DEMO.md](DEMO.md) | 60-second quickstart and full demo script |

## Conventions

- **Planned vs shipped:** every doc states its status. Commands are only written as shipped after they run in CI or a recorded demo.
- **Sources:** security claims link to NEAR docs or public reports with a retrieval date. No unsourced claims.
- **Corrections:** open an issue with the doc name and the claim. Corrections are welcome and credited.
- **Built with thecoding:** nearsc was engineered with AI coding agents (OpenCode) against the NEAR Hackathon rules. The pre-hackathon prompt-stack version (tagged `pre-hackathon`) is the baseline; everything above it is the hackathon rewrite (Q-005).
