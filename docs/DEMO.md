# Demo

> **Status:** script for the v0.1 demo (2026-11-09, updated 2026-11-12; the agent demo is verified real). `nearsc` 0.1.2 is published on crates.io, so `cargo install nearsc` is the installed path. The 60-second quickstart is the path a judge or screener follows.

## 60-second quickstart (from source, real today)

```bash
# 1. Clone the repo with the deliberately vulnerable example
git clone https://github.com/vinibarbosabr/nearsc-auditor
cd nearsc-auditor

# 2. Scan (from source; or install the published 0.1.2 with `cargo install nearsc`)
cargo run -p nearsc -- scan examples/vulnerable-contract

# 3. Scan the patched twin: same surface, every seed fixed, zero findings
cargo run -p nearsc -- scan examples/fixed-contract
```

Expected shape of the output (real run captured 2026-11-12 from this tree; regenerate if the fixture changes):

```text
$ cargo run -p nearsc -- scan examples/vulnerable-contract
HIGH     NS001 src/lib.rs:58 transfer method `ft_transfer` does not enforce the 1-yoctoNEAR attached deposit; add assert_one_yocto() or an equivalent check (NEP-141/171)
MEDIUM   NS012 src/lib.rs:82 public setter `set_owner` changes privileged state or moves funds without a guard; restrict it with #[private] or assert predecessor == owner/current_account_id
HIGH     NS002 src/lib.rs:87 callback `on_deposit_complete` can be invoked by any account; add #[private] or assert predecessor == current_account_id
MEDIUM   NS003 src/lib.rs:95 callback `on_withdraw_result` can panic on attacker-influenced input; handle failure explicitly instead of unwrap/expect/indexing
HIGH     NS004 src/lib.rs:111 function `on_deposit_result` consumes a promise result without matching PromiseResult::Failed; state can advance on a failed cross-contract call
CRITICAL NS006 src/lib.rs:119 function `set_state` writes contract state without an access-control guard; a caller can overwrite it. Add #[private] or assert predecessor == current_account_id / owner
LOW      NS011 src/lib.rs:137 payable method `claim` can return early after the deposit attached and shows no refund path; refund the attached deposit on every early exit or document why funds may stay
MEDIUM   NS009 src/lib.rs:145 `draw_winner` derives a value from block data or the caller's account; those inputs are predictable or influenceable, so lotteries/mints built on them can be steered. Use a commit-reveal or a random-seed oracle
MEDIUM   NS008 src/lib.rs:153 public method `free_note` stores caller-controlled data without an attached deposit or storage check; charging for storage (or requiring it up front) keeps the contract's balance from being drained
MEDIUM   NS007 src/lib.rs:159 public method `total_pending` loops over a collection that callers can grow without a bound; add pagination or cap the iteration before gas makes this method uncallable
HIGH     NS010 src/lib.rs:166 public method `notify_receiver` builds a Promise::new target from caller input without an allowlist check; restrict targets to state-derived values or an allowlist before the contract pays or calls attacker-chosen accounts
CRITICAL NS005 src/lib.rs:182 ignore_state init `migrate` is not access-controlled; any account can reinitialize contract state. Add #[private] or assert predecessor == current_account_id
12 findings (critical 2, high 4, medium 5, low 1, info 0)
disclaimer: 10 of 12 findings are heuristic-confidence review hints; expect false positives and confirm each one by hand
```

```text
$ cargo run -p nearsc -- scan examples/fixed-contract
0 findings (critical 0, high 0, medium 0, low 0, info 0)
```

```bash
# 4. Human-readable report
cargo run -p nearsc -- scan examples/vulnerable-contract --format html --output report.html

# 5. Machine formats
cargo run -p nearsc -- scan examples/vulnerable-contract --format json
cargo run -p nearsc -- scan examples/vulnerable-contract --format sarif
```

## Agent demo (real, 2026-11-12)

Run an agent session with the MCP server configured ([MCP.md](MCP.md)) and ask:

```
Audit examples/vulnerable-contract with nearsc: scan it, take the top
critical/high finding, pull its pattern and one real audit precedent, check
the counterparty intents.near on mainnet, and scaffold a PoC for the
callback finding. Summarize what to fix first.
```

Verified live in the gate session (2026-11-12): the agent calls `nearsc_scan`
(12 findings: critical 2, high 4, medium 5, low 1), `nearsc_patterns` (NS006
upgrade-path-unguarded with vulnerable/fixed code), `nearsc_audits`
(sputnikdao2 storage_withdraw precedent + the NEAR Intents postmortem),
`nearsc_contract_info` (intents.near: registry MATCH, 2 audit links), and
`nearsc_poc_scaffold` (nearsc-poc-ns002 skeleton). Negative probes (scan of
`/etc`, account id `WRAP.NEAR`) return structured tool errors. Capture the
same flow on video from a fresh session.

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

## Hardened-codebase false-positive check

A scanner that cries wolf on audited code is noise. The reference measurement is the `sputnik-dao-contract` snapshot (sputnikdao2, factory2, staking, test-token: exhaustively audited, in production for years):

```bash
git clone --depth 1 https://github.com/near-daos/sputnik-dao-contract /tmp/sputnik
cargo run -p nearsc -- scan /tmp/sputnik
```

The campaign is documented in [FALSE-POSITIVES.md](FALSE-POSITIVES.md): v0.1.0 emitted 29 findings on the snapshot, v0.1.1's ABI gate cut it to 6, and v0.1.2 reports 2 (critical 0, high 1, medium 1): the NS013 drain in `sputnik-staking` that the baseline rule set missed (the issue #239 class), plus one deliberately kept NS003 review hint in `sputnikdao2`. Both are labeled heuristic, the text output discloses the count, and `--min-confidence spec` reports zero. Recall went up while noise went down.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `nearsc: command not found` | `cargo install nearsc` (0.1.2 is published) or use `cargo run -p nearsc -- scan <path>` |
| No findings on your own contract | Check the path points at Rust sources; run `nearsc rules list` to see active rules |
| Parse errors in the output | The file uses syntax syn cannot parse; findings elsewhere are still valid |
| MCP tool not listed | Restart the harness after editing its MCP config; check the binary is on PATH; when running from a checkout, point the config at `cargo run -p nearsc-mcp` |
| `nearsc_scan` errors with "escapes the working directory" | Pass paths relative to the project the harness opened; the server never scans outside it |

## For judges

The scan path is offline and deterministic: the same input produces the same findings on any machine. The repo includes the vulnerable example so the result is reproducible without cloning a third-party project.
