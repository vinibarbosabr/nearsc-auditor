# Roadmap

> **Status:** direction document (2026-11-09, updated 2026-11-16). Dates are targets, not commitments. v0.1 shipped during the NEAR Hackathon 2026 window (crates.io packaging landed with `v0.1.0` on Nov 13; v0.1.2 is the submitted release, pinned at the `hackathon-submission` tag). The v0.2.0 milestone (issues #81-#90, opened 2026-11-16) covers the scan hardening campaign and the KB catalogue expansion; the analysis-lift items are v0.2.x follow-ups, not part of the December milestone.

## v0.1: hackathon release (Nov 2026)

- 12 NEAR-specific rules with fixture pairs (13 with NS013, added in the v0.1.2 hardening pass).
- CLI: text, JSON, SARIF, single-file HTML reports.
- MCP server: scan, patterns, audits, contract info, PoC scaffold (shipped, with stdio contract tests).
- Knowledge base: patterns, public audits, postmortems, contract registry (shipped, embedded in the binary).
- Agent skill v2 (`nearsc-skill/SKILL.md`) and a composite GitHub Action (`action/`, dogfooded with SARIF upload).
- MIT license; crates.io packages `nearsc` and `nearsc-mcp`.

## v0.2.0: scanner hardening + KB catalogue (Dec 2026)

Tracked as milestone issues #81-#90:

- **Scan hardening campaign.** Run the scanner against 8 production NEAR contracts (near-contract-standards, PotLock, Burrow, HERE LST, Meta Pool, Ref Finance, Mintbase, Sweat Economy) plus a sputnik-dao-contract regression re-run (#81, #82). Every finding is triaged per [FALSE-POSITIVES.md](FALSE-POSITIVES.md); fixable false positives become matcher corrections under the safety bar (#83); clear misses become new rules backed by audit precedent (#84).
- **KB catalogue expansion.** +10 audits from the vault backlog (D-017), per-finding blocks for the five summary-depth entries, cross-index stats (pattern → audits derived from vector tags), and the public `docs/KB-BACKLOG.md` page (#85-#88).
- **Contributor + distribution polish.** Rule authoring guide and a `nearsc rules new` scaffold (#89); a prebuilt composite GitHub Action without the `cargo install` step (#90).

## v0.2.x: analysis depth (Dec 2026 – Q1 2027, follow-ups)

- **Macro-aware analysis.** Expand near-sdk macros (`ra_ap_*` or `cargo expand`) so rules see generated code. The threat model changes here: macro expansion compiles and runs proc-macros, which crosses the "parse, never execute" line - this needs an ADR and an opt-in flag before any implementation.
- **Promise-flow analysis.** Track a cross-contract call from `.then()` to callback and flag unhandled failure paths across functions; also the dataflow needed for cross-file callback resolution (NS002), amount↔state binding precision for NS010/NS013, and internal-helper routing for the ABI gate.
- **NEP conformance pack.** Rules for NEP-141/171/245 edge cases beyond transfers (metadata, approvals, receiver interfaces). Informed by the near-contract-standards leg of the scan campaign (#81).

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

## Prior-art notes (2026-11-16 research, for future versions)

What the equivalent ecosystems ship, and what is worth borrowing for v0.3+. Nothing here
changes the v0.2.0 scope above; each note is a candidate for a future milestone.

| Tool | Scope | Architecture | License | Worth borrowing |
| --- | --- | --- | --- | --- |
| [Slither](https://github.com/crytic/slither) (crytic/Trail of Bits) | Solidity / EVM | Custom IR (SlithIR, SSA) + detectors + printers | AGPL-3.0 / licensed | Detector doc conventions: per-detector prose with impact × confidence; `--list-detectors`; triage culture around accepted noise. nearsc's severity+confidence labels already mirror the axes |
| [radar](https://github.com/Auditware/radar) (Auditware) | Rust/Anchor/Stylus/Solidity | Python rule templates over parsed Rust | GPL-3.0 | Shareable, templated rule authoring; `--fail-on` exit-code contract (nearsc already matches it); "test code out of scope by default" as an explicit, documented default |
| [Eloizer](https://inversive.xyz/blog/Eloizer/) (Inversive Labs, 2026-01) | Solana | `syn` + `anchor-syn` parse, rule DSL, no compilation | (blog/tool) | Closest architectural sibling to nearsc. Their tradeoff statement is ours too: source-level analysis finds structural patterns, full dataflow needs type information. Their rule-DSL ergonomics inform the `rules new` scaffold (#89) |
| [X-Ray](https://github.com/sec3-product/x-ray) (sec3.dev) | Solana | AST → LLVM-IR → rule engine | AGPL-3.0 | Compile-to-IR as the precision path if dataflow is ever added; IntegerOverflow/Underflow rule family parallels the arithmetic/precision candidate class |
| [solana-lints](https://github.com/crytic/solana-lints) (Trail of Bits) | Solana | Dylint compiler-plugin lints (runs inside rustc) | AGPL-3.0 | The "compile-first" alternative architecture; useful contrast when the macro-aware ADR weighs `ra_ap_*` vs `cargo expand` |
| [solana-fender](https://github.com/honey-guard/solana-fender) | Solana/Anchor | Rust crate + CLI, usable in unit tests | GPL-3.0 | Distribution as a crate that projects call inside their own tests |

**Research findings parked here for later versions (v0.3.0+):**

- **NEP conformance pack as a first-class product** (currently v0.2.x follow-up). NEAR has
  no equivalent of Slither's "EVM spec suite"; a NEP-141/171/245 conformance tier
  (metadata, approvals, receiver interface, storage-withdraw shape) would be unique among
  NEAR tooling. v0.3 candidate: conformance mode with a stable exit-code contract.
- **Crate-as-lint distribution** (solana-fender model): ship `nearsc` as a dev-dependency
  so projects can assert scan cleanliness inside `cargo test`. Cheap to add once the
  library API is stable.
- **Cross-index/public-facing precedent search** (v0.2.0 #86 is the internal step):
  the 2026-11-12 KB session already surfaced the vector-tag classes; a v0.3 candidate is
  exposing "class → real-world precedent" through the MCP tools so agents can cite audits
  in findings without leaving the session.
- **v1.0.0 shape (needs more research; unresolved):** the gap between "static analyzer
  that ships findings" and "tool a team trusts as a release gate" is likely closed by
  three things: proven precision numbers from the #81 campaign, a stable rule-versioning
  story (rule ids frozen so SARIF consumers can fingerprint), and a conformance tier.
  Do not schedule v1 until the hardening campaign produces real precision data.

Judged notes: the NEAR Hackathon 2026 landscape scan (vault-only, competitive intel) is
deliberately not cited in public docs per that scan's own guidance.

