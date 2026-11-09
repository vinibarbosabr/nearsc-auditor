# Comparison: prior art and where nearsc fits

> **Status:** analysis as of 2026-11-09. Tool capabilities change; verify current behavior before relying on this table. Corrections welcome.

## Prior art

| Tool | Chain / scope | What it does well | What it does not do for NEAR |
| --- | --- | --- | --- |
| **Slither** | Solidity / EVM | Mature static analysis, detectors, printers, CI integration | No Rust, no async promises, no NEAR storage model |
| **Echidna / Medusa** | EVM | Property-based fuzzing | No NEAR runtime; fuzzing NEAR needs workspaces-rs |
| **Mythril** | EVM | Symbolic execution | EVM-specific |
| **semgrep** | Generic | Fast pattern rules across languages | Generic patterns only; no NEAR semantics, no NEP standards |
| **clippy** | Rust | General Rust lints | Knows nothing about near-sdk, promises, storage staking, or NEPs |
| **cargo-audit** | Rust ecosystem | Dependency advisories | Dependencies only, not contract logic |
| **cargo-geiger** | Rust | Unsafe usage metrics | Not a vulnerability scanner |
| **near-cli-rs** | NEAR | Account and contract operations | Not an analyzer |
| **workspaces-rs** | NEAR | Integration testing and PoCs | A framework, not a scanner |
| **near-sdk-rs** | NEAR | Contract framework | Compile-time checks only |

## The gap nearsc targets

1. **NEAR semantics are the rules.** Async promise flows, callback privacy, 1-yocto authorization, storage staking, NEP conformance. General Rust tools cannot express these; EVM tools cannot see them.
2. **Precedent, not just patterns.** Findings link to real NEAR audit reports and postmortems, with sources and confidence labels.
3. **Agent-native.** An MCP server so coding agents and autonomous agents can scan and verify contracts as part of their workflow.
4. **Deterministic and offline.** Reproducible findings for CI and audits, no model in the scan path.

## What nearsc is not

- Not a Slither port: the rule engine is NEAR-specific, not EVM-derived.
- Not a fuzzer: v0.1 does not execute contracts. PoC scaffolding hands off to workspaces-rs.
- Not a replacement for an audit: a first pass that raises the floor.

## Honest status of the NEAR tooling landscape

As of November 2026, we found no dominant open-source static analyzer purpose-built for NEAR contracts. Audits are performed by firms and independent researchers with private checklists. This comparison is based on public information and our own scan of the ecosystem; if a comparable tool exists, open an issue and it will be added here with an honest assessment.

## Where to plug in

| Need | Use |
| --- | --- |
| Fast pre-deploy check | `nearsc scan` |
| CI gate | GitHub Action + SARIF |
| Agent audit workflow | `nearsc-mcp` |
| Deeper manual audit | nearsc findings + workspaces-rs PoCs + a human auditor |
| Fuzzing | `cargo-fuzz` or workspaces-rs property tests (roadmap: generated targets) |
