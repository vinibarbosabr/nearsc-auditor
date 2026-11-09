# Demo

> **Status:** script for the v0.1 demo (2026-11-09). Commands marked planned land with the `v0.1.0` tag. The 60-second quickstart is the path a judge or screener follows.

## 60-second quickstart (planned)

```bash
# 1. Install (crates.io, after v0.1.0)
cargo install nearsc

# 2. Clone the repo with the deliberately vulnerable example
git clone https://github.com/vinibarbosabr/nearsc-auditor
cd nearsc-auditor

# 3. Scan
nearsc scan examples/vulnerable-contract
```

Expected shape of the output (counts and line numbers depend on the fixture):

```
nearsc 0.1.0 · examples/vulnerable-contract · 4 files

HIGH     NS002  callback-not-private          src/lib.rs:142
HIGH     NS001  one-yocto-missing-on-transfer src/lib.rs:88
CRITICAL NS005  init-ignore-state-unguarded    src/lib.rs:41
MEDIUM   NS008  storage-griefing               src/lib.rs:210

4 findings: 1 critical, 2 high, 1 medium · run with --format html for a report
```

```bash
# 4. Human-readable report
nearsc scan examples/vulnerable-contract --format html --output report.html

# 5. Machine formats
nearsc scan examples/vulnerable-contract --format json
nearsc scan examples/vulnerable-contract --format sarif
```

## Agent demo (planned)

Start an agent session with the MCP server configured ([MCP.md](MCP.md)), then ask:

```
Audit examples/vulnerable-contract with nearsc. For each high or critical
finding, pull the pattern guidance and one real audit precedent, then
scaffold a workspaces-rs PoC for the callback finding.
```

The agent calls `nearsc_scan`, `nearsc_patterns`, `nearsc_audits`, and `nearsc_poc_scaffold`, and produces a report with fixes in priority order.

## Full demo video script (2:00)

| Time | Shot | Voice-over / caption |
| --- | --- | --- |
| 0:00–0:20 | Vulnerable callback snippet on screen | "NEAR contracts are async. A callback without `#[private]` can be called by anyone. This is one of the bugs that ships." |
| 0:20–1:00 | Terminal: `nearsc scan`, findings table, then `--format html` and scroll | "One command. Deterministic findings. A report you can hand to a reviewer." |
| 1:00–1:35 | Agent session over MCP: scan, pattern, precedent, PoC scaffold | "Your agent gets the same engine, plus the knowledge base: why it matters, what it looked like in real audits, and a PoC to prove it." |
| 1:35–1:55 | GitHub Action: PR diff with SARIF annotations | "And it runs in CI, so the bug never reaches main." |
| 1:55–2:00 | Repo + crates.io links | "nearsc. Scan your contract before your agent signs." |

Recording notes:

- No slides, no intro animation. Terminal font large enough for mobile.
- Cut dead time between commands; keep one continuous take per segment if possible.
- Show real output, not mockups.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `nearsc: command not found` | `cargo install nearsc` or use `cargo run -p nearsc -- scan <path>` |
| No findings on your own contract | Check the path points at Rust sources; run `nearsc rules list` to see active rules |
| Parse errors in the output | The file uses syntax syn cannot parse; findings elsewhere are still valid |
| MCP tool not listed | Restart the harness after editing its MCP config; check the binary is on PATH |

## For judges

The scan path is offline and deterministic: the same input produces the same findings on any machine. The repo includes the vulnerable example so the result is reproducible without cloning a third-party project.
