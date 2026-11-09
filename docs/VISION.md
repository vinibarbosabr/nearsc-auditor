# Vision: the security layer for NEAR builders and their agents

> **Status:** design document (2026-11-09). Nearsc v0.1 is being built during the NEAR Hackathon 2026; see the root README for shipped status.

## The problem

NEAR smart contracts are Rust compiled to WASM, running on an async, promise-based runtime where the classic safety intuitions from other chains do not transfer:

- **Cross-contract calls are asynchronous.** There is no atomicity across contracts; callbacks arrive in a later receipt and can fail, be reordered, or be invoked by an attacker if not guarded.
- **Storage is money.** Contracts stake NEAR for every byte they store (~1 NEAR per 100 KiB). Unbounded inserts are a griefing vector, not just a gas concern.
- **Authorization has sharp edges.** The 1-yoctoNEAR attachment pattern, `#[private]` callbacks, and predecessor checks are load-bearing; each one is easy to omit and hard to notice in review.
- **Macros hide the surface.** `#[near_bindgen]`, `#[init]`, `#[payable]`, and `#[private]` change runtime behavior in ways that a generic linter does not model.

Today, catching these issues depends on a manual audit, usually after the contract ships. Builders get no fast, deterministic feedback loop, and agents that call contracts have no way to check what they are about to touch.

## The insight

Most NEAR exploits cluster in a small set of patterns: callback hijacks, unguarded init/migrate paths, unchecked promise results, storage griefing, and missing 1-yocto authorization. These are **syntactically detectable** in the Rust source with high precision, without a compiler, without execution, and without a model.

A deterministic scanner over those patterns, paired with real audit precedent, turns a post-hoc audit into a pre-deploy habit.

## The product

Three layers, one binary each:

1. **Scanner (`nearsc`).** Parses Rust source, applies 12 NEAR-specific rules, emits findings as text, JSON, SARIF, or a single-file HTML report. Deterministic and offline.
2. **Knowledge base.** Real NEAR audit reports, postmortems, and vulnerability classes, summarized with sources and confidence labels. Every finding can point to precedent.
3. **Agent interface (`nearsc-mcp`).** An MCP server so coding agents and autonomous agents can scan a repo, look up a pattern, search precedent, check a contract's on-chain reputation, and scaffold a proof of concept.

## Who it is for

| User | Job to be done |
| --- | --- |
| NEAR builder | Run one command before deploying; catch the classic bugs in CI |
| Security researcher | Triage a repo in minutes; jump from a finding to real precedent |
| Coding agent (Claude Code, Codex, opencode, Cursor) | Audit code through MCP tools instead of guessing from memory |
| Autonomous agent | Check a contract before paying or calling it: code hash, age, known audit status |
| Auditor | Use the KB and PoC scaffold as a starting point, not a replacement for judgment |

## Why now

- AI agents are getting wallets. The hackathon theme, "money with a mind of its own", only works if agents can verify what they interact with.
- The NEAR ecosystem has no open, NEAR-native static analyzer. General tools (clippy, cargo-audit, semgrep) do not model async promises, storage staking, or NEP standards.
- The audit market is manual and expensive; a deterministic first pass raises the floor for every team.

## What nearsc is not

- **Not a replacement for an audit.** It is a fast, deterministic first pass. Findings need human judgment.
- **Not a runtime firewall.** It does not sit between an agent and a chain at execution time.
- **Not an LLM oracle.** The scanner never calls a model. AI belongs in the orchestration layer, not in the finding.
- **Not chain-agnostic (yet).** The rules encode NEAR semantics on purpose.

## How we measure success

1. A builder runs `nearsc scan` before deploying and fixes a real finding.
2. An agent session audits a contract end-to-end through MCP and produces a report a human can review.
3. A finding links to public precedent, so a reviewer can see why it matters.
4. The KB grows with public reports from the community, with sources and confidence labels.
