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

## D-007: name nearsc

**Decision:** repo `nearsc-auditor`, CLI and crate `nearsc`, MCP binary `nearsc-mcp`.

**Why:** instant clarity for search and npm-style discovery ("near" + "audit"), short CLI, room for the `-auditor` repo name. The pitch line ("the Slither for NEAR") carries the story; the name does not need to.

## D-008: MIT license, summarized third-party content

**Decision:** MIT repo-wide. KB entries summarize and cite; verbatim copies only with a compatible license and attribution.

**Why:** maximum adoption; clean legal posture for a public-goods tool.
