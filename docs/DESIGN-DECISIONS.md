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

**Decision:** embed rules TOML, KB files, and the registry via `include_dir`.

**Why:** single-binary installs, deterministic builds, no runtime data path configuration. KB updates ship as releases.

**Consequences:** no hot-swappable data directory in v0.1; acceptable for the current scale.

## D-006: rules as TOML metadata + Rust matchers

**Decision:** metadata (severity, refs, snippets, message) in `rules/*.toml`; detection in Rust matchers; a parity test keeps them in sync.

**Why:** one source of truth for the CLI findings, the MCP pattern lookup, and the docs. Contributors can improve metadata without touching the engine; matchers stay type-safe.

**Scheduling note (2026-11-11, confirmed with the owner):** the TOML layer and the `include_dir` embedding land Thursday morning, immediately before the five MCP tools are built, and include moving `data/` and `rules/` under `crates/nearsc/` so the embedded paths resolve both from a git checkout and from a crates.io package. It cannot slip later: the crates.io publish (issue #10) requires the embedded data, and the MCP pattern tool is its first consumer.

## D-007: name nearsc

**Decision:** repo `nearsc-auditor`, CLI and crate `nearsc`, MCP binary `nearsc-mcp`.

**Why:** instant clarity for search and npm-style discovery ("near" + "audit"), short CLI, room for the `-auditor` repo name. The pitch line ("the Slither for NEAR") carries the story; the name does not need to.

## D-008: registry ships empty; seeds follow the audit KB

**Context:** the registry maps NEAR contract accounts to audited code hashes. A hash is trivially verifiable on-chain; the "audited" claim is only honest when a public audit exists that we can link. A registry entry without that link would be invented trust, which the KB sourcing rules (verified-public, no unsourced claims) forbid. Which projects can honestly be claimed is therefore a function of how many sourced audit summaries the KB holds - the KB must expand before meaningful seeds exist.

**Decision (2026-11-11):** Wednesday ships the RPC lookup (`nearsc contract <account_id>`), the `data/registry.json` schema, and the loader/matcher code path, with an empty registry. Registry seeding (3-5 entries) lands after the KB expansion session, drafted from the expanded audit KB. The EOD gate `nearsc contract wrap.near` returns a code hash is satisfied by the RPC fetch alone (it is optional and outside the scan-path determinism contract).

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

> **Numbering note (2026-11-11):** this page's D-numbers are this page's own edition of the decision log; the working log in the vault is longer and does not mirror these ids one-to-one. The scheduling records in D-006 (TOML + embedding land Thursday morning, before the MCP build) and D-008 (registry ships empty; seeding follows the audit KB) are the authoritative versions of those two decisions.
