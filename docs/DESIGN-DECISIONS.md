# Design decisions (public ADRs)

> **Status:** public subset of the project decision log (2026-11-09). Internal-only decisions (submission strategy, personal matters) are excluded.

## D-001: Rust + cargo, not TypeScript + npm

**Context:** the first plan used TypeScript for MCP SDK maturity and `npx` convenience. The audience and the analysis ceiling argue otherwise.

**Decision:** Rust workspace; crates.io packages `nearsc` (lib + CLI) and `nearsc-mcp` (server); prebuilt release binaries.

**Why:**
- NEAR contracts are Rust→WASM; near-cli-rs, workspaces-rs, and nearcore are Rust. The users already have cargo.
- A Rust tool sits natively in the NEAR tooling family; an npm tool is a guest.
- The analysis ceiling is higher: `syn`, `ra_ap_*`, and `wasmparser` are the canonical path to macro-aware and WASM-level analysis.
- PoC scaffolds target workspaces-rs, which is Rust.

**Consequences:** npm is not needed; crates.io publishing and release binaries are part of the release plan.

## D-002: syn-based AST, not tree-sitter, not regex

**Decision:** parse with `syn`; rules are typed AST visitors. Regex only as a secondary matcher type.

**Why:** syn is the canonical Rust parser with no C grammar dependency; near-sdk macros are attribute macros and are syntactically visible; type-aware analysis can come later through rust-analyzer crates. Regex-first would raise false positives on comments, strings, and doc examples.

**Consequences:** exotic macro-heavy files may fail to parse; the engine records parse errors as info and never crashes.

## D-003: deterministic engine, no LLM

**Decision:** findings reproduce byte-for-byte; no model calls in the scan path. AI lives in the MCP/skill orchestration layer.

**Why:** screeners, CI, and audit defensibility all require determinism. A model in the engine makes findings unreproducible and unauditable.

## D-004: MCP server as a first-class surface

**Decision:** ship `nearsc-mcp` with five read-only tools, in a separate crate.

**Why:** agents are a real audience for contract security (they write contracts and call them). A separate crate keeps the CLI install lean. MCP is harness-agnostic.

**Consequences:** an async runtime (tokio) is confined to the MCP crate.

## D-005: data embedded in the binary

**Decision:** embed the KB (patterns, audits, postmortems, generated index) and the audited-build registry via `include_dir`/`include_str!`, shipped 2026-11-11 (PR #63). `data/` moved to `crates/nearsc/data/` so the embedded paths resolve both from a git checkout and from a crates.io package.

**Why:** single-binary installs, deterministic builds, no runtime data path configuration. KB updates ship as releases.

**Consequences:** no hot-swappable data directory in v0.1; acceptable for the current scale. `nearsc kb-index` remains the checkout-only regeneration command.

## D-006: rules as code catalog + Rust matchers

**Decision:** rule metadata lives in the `CATALOG` table in `crates/nearsc/src/rules/mod.rs`; detection in Rust matchers in the same tree; a parity test keeps them in sync. The earlier plan for a separate `rules/*.toml` layer was dropped on 2026-11-11 (with the owner): the catalog table serves the same single-source-of-truth role for the CLI findings, the MCP pattern lookup, and `docs/RULES.md`, without a second format to keep compiled.

**Why:** one source of truth, no drift between what ships and what the docs claim; matchers stay type-safe.

**Scheduling note (2026-11-11, confirmed with the owner):** the TOML layer was superseded by the catalog-table decision above; the `include_dir` embedding of `data/` landed as planned (PR #63) before the five MCP tools (PR #64) were built.

## D-007: name nearsc

**Decision:** repo `nearsc-auditor`, CLI and crate `nearsc`, MCP binary `nearsc-mcp`.

**Why:** instant clarity for search and npm-style discovery ("near" + "audit"), short CLI, room for the `-auditor` repo name. The pitch line ("the Slither for NEAR") carries the story; the name does not need to.

## D-008: registry ships empty; seeds follow the audit KB

**Context:** the registry maps NEAR contract accounts to audited code hashes. A hash is trivially verifiable on-chain; the "audited" claim is only honest when a public audit exists that we can link. A registry entry without that link would be invented trust, which the KB sourcing rules (verified-public, no unsourced claims) forbid. Which projects can honestly be claimed is therefore a function of how many sourced audit summaries the KB holds - the KB must expand before meaningful seeds exist.

**Decision (2026-11-11):** shipped the RPC lookup (`nearsc contract <account_id>`), the `crates/nearsc/data/registry.json` schema, and the loader/matcher code path; the registry was then seeded (3 entries) after the KB expansion session, drafted from the shipped audit KB. The EOD gate `nearsc contract wrap.near` returns a code hash is satisfied by the RPC fetch alone (it is optional and outside the scan-path determinism contract).

**Amendment (2026-11-12, D-017 session):** the registry is seeded with `contract.main.burrow.near`, `intents.near`, and `v2.ref-finance.near`; `code_hash` values fetched live via RPC, each entry backed by shipped audit/postmortem entries with explicit coverage caveats (the BlockSec audits cover 2022 commits, the Guvenkaya audit covers the Feb 2025 baseline; deployed code has changed since in both cases and the entries say so).

## D-009: MIT license, summarized third-party content

**Decision:** MIT repo-wide. KB entries summarize and cite; verbatim copies only with a compatible license and attribution.

**Why:** maximum adoption; clean legal posture for a public-goods tool.

---

## D-010: heuristic rules scope to explicit API use, not macro idioms

**Context:** the original NS004 spec text said to flag "`#[callback]` usage where failure handling is expected". Every near-sdk `#[callback]`/`#[callback_vec]` deserialization unwraps internally and panics on failure by design, so the literal reading flags idiomatic, correct code.

**Decision (2026-11-10, with Vini):** NS004 flags explicit `env::promise_result` / `PromiseResult` consumption without a `PromiseResult::Failed` match or if-let arm. `#[callback*]` parameters are not flagged; the macro's unwrap-and-panic behavior is documented semantics. Same principle applied to NS006: v0.1 flags direct `state_write` call sites in unguarded functions; migrate-deserialization reachability waits for v0.2 dataflow analysis.

**Why:** a heuristic rule's value is signal per finding. Flagging by-design macro behavior trains users to ignore the tool, which is the worst outcome for a security scanner. Docs note the macro behavior instead (docs/RULES.md, NS004 "Amended scope").

**Consequences:** callbacks that rely on `#[callback]`'s panic-on-failure are not findings; reviewers reading such code should ask whether a silent panic mid-flow is acceptable there. The amendment and its date are recorded in docs/RULES.md per rule.

## D-011: recall over precision — the false-positive policy

**Context:** the first live test against a real hardened contract (sputnik-dao-contract, git `5434a59`, 2026-11-12) produced 29 findings: 25 defensible false positives, 3 partial true positives — and, the headline, the strongest real bug in the snapshot (a repeatable `storage_withdraw` drain) sat outside the rule set entirely. The temptation after such a scan is to quiet the matcher until the output looks clean.

**Decision (2026-11-12, with Vini):** nearsc optimizes for recall and discloses precision. False positives are handled by confidence labels, the per-scan heuristic disclaimer, per-rule FP documentation, and matcher corrections that clear a conservative safety bar — never by deleting rules, disabling detection, or exempting shapes without a negative-control fixture proving a real bug in the same shape still fires. Full policy: [FALSE-POSITIVES.md](FALSE-POSITIVES.md).

**Why:** a security scanner's failure modes are asymmetric. A false positive costs minutes and is disclosed as such; a false negative can cost a treasury. The sputnik campaign is the worked example: FP count on the snapshot went 25 → 0 across v0.1.0 → v0.1.2 while the rule set *gained* the class (NS013) that catches the drain the baseline found only by hand.

**Consequences:** the scanner stays intentionally noisy on some hardened code, and the disclaimer carries that contract with the user. Every FP fix ships a negative control; the hardened-reference regression (a real finding may never be dropped) gates merges. Contributor PRs that relax a matcher without a negative control are rejected by the review checklist.

> **Numbering note (2026-11-11):** this page's D-numbers are this page's own edition of the decision log; the working log in the vault is longer and does not mirror these ids one-to-one. The scheduling records in D-006 (TOML + embedding land Thursday morning, before the MCP build) and D-008 (registry ships empty; seeding follows the audit KB) are the authoritative versions of those two decisions.
