# Roadmap

> **Status:** direction document (2026-11-09, updated 2026-11-12). Dates are targets, not commitments. v0.1 ships during the NEAR Hackathon 2026 window; the v0.1 list below is shipped except crates.io packaging (lands with the `v0.1.0` tag on Nov 14).

## v0.1: hackathon release (Nov 2026)

- 12 NEAR-specific rules with fixture pairs.
- CLI: text, JSON, SARIF, single-file HTML reports.
- MCP server: scan, patterns, audits, contract info, PoC scaffold (shipped, with stdio contract tests).
- Knowledge base: patterns, public audits, postmortems, contract registry (shipped, embedded in the binary).
- Agent skill v2 (`skill/SKILL.md`) and a composite GitHub Action (`action/`, dogfooded with SARIF upload).
- MIT license; crates.io packages `nearsc` and `nearsc-mcp`.

## v0.2: depth (Dec 2026 – Jan 2027)

- **Macro-aware analysis.** Expand near-sdk macros (`ra_ap_*` or `cargo expand`) so rules see generated code.
- **Promise-flow analysis.** Track a cross-contract call from `.then()` to callback and flag unhandled failure paths across functions.
- **KB catalogue completion.** Convert the audit backlog through the depth tiers, ship cross-index stats (pattern → audits, derived from vector tags) and a public backlog page; upgrade the per-finding blocks for the summary-depth entries (tables already classified per PR #60).
- **NEP conformance pack.** Rules for NEP-141/171/245 edge cases beyond transfers (metadata, approvals, receiver interfaces).
- **Rule authoring guide** and a `nearsc rules new` scaffold for contributors.
- **Prebuilt GitHub Action** (no `cargo install` step).

## v0.3: deployed-code checks (Q1 2027)

- **WASM-level analysis** (`wasmparser`): compare deployed code against a known audited build; detect suspicious import patterns.
- **Contract reputation API:** age, code changes, admin key shape, audit status, all from public chain data.
- **Registry growth:** community-submitted audited builds with verification instructions.

## v0.4: workflow integration (Q2 2027)

- Editor/LSP integration for inline findings.
- GitLab CI and generic SARIF upload recipes.
- Fuzzing handoff: generate `cargo-fuzz` targets from findings instead of pretending to fuzz.
- Rule packs for common contract families (FT, NFT, DAO, vault, staking).

## Explicit non-goals

- **Runtime firewall.** nearsc does not sit between an agent and a chain.
- **LLM in the engine.** Findings stay deterministic.
- **A hosted service.** The binary and MCP server are the product.
- **Chain-agnostic rules.** NEAR semantics are the point.

## How to influence the roadmap

Open an issue with the use case and the contract pattern. Rules with a public precedent, a fixture pair, and a fix snippet move to the top.
