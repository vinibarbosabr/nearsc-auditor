# Architecture

> **Status:** design document (2026-11-09). Describes the planned v0.1 structure; file names may shift during the build. The root README tracks what is shipped.

## Overview

```
┌──────────────┐     ┌─────────────────────────────┐     ┌──────────────────┐
│  CLI (clap)  │────▶│  Engine (syn AST + rules)   │────▶│  Reports         │
│  nearsc      │     │  walk → parse → match       │     │  text/json/sarif │
└──────────────┘     └──────────────┬──────────────┘     │  /html           │
                                    │                     └──────────────────┘
┌──────────────┐                    │
│ MCP server   │────────────────────┘
│ nearsc-mcp   │     ┌─────────────────────────────┐
│ (rmcp/stdio) │────▶│  Knowledge base (embedded)  │
└──────────────┘     │  patterns, audits, registry │
                     └─────────────────────────────┘
```

Everything ships in one cargo workspace. The CLI and the MCP server share the same library crate, so a finding produced by an agent is byte-identical to one produced in CI.

## Crates

| Crate | Kind | Responsibility |
| --- | --- | --- |
| `nearsc` | lib + bin | Engine, rules, reports, RPC, KB access, CLI |
| `nearsc-mcp` | bin | MCP stdio server, five tools, thin layer over `nearsc` |

Keeping the MCP server in a separate crate means `cargo install nearsc` does not pull tokio or rmcp.

## Pipeline

1. **Walk.** Recursively collect `*.rs` files under the target path, skipping `target/`, `.git/`, and `node_modules/` by default. A directory passed explicitly as the target is always scanned, even when its name matches a skipped directory.
2. **Parse.** `syn::parse_file` per file. Parse errors become `parse_errors` entries, never fatal.
3. **Context.** For each file, index functions, attributes, trait impls, and call sites (`.then()`, `Promise::new`, `env::*`).
4. **Match.** Run registered matchers. Each matcher is a pure function `(&FileContext) -> Vec<Finding>`.
5. **Merge.** Stable sort by `(file, line, rule_id)`. Deduplication is not implemented in v0.1: no shipped rule can emit two findings for one location. If a future rule can, add the dedup step here and update this note.
6. **Report.** Render text, JSON, SARIF, or HTML.

Determinism: no network in the scan path, no timestamps inside findings, no parallelism-dependent ordering in v0.1.

## Rule system

Rules have two halves:

- **Metadata** in `rules/<ID>.toml`: id, title, severity, confidence, matcher name, tags, refs, message, vulnerable snippet, fixed snippet. Embedded via `include_dir`.
- **Matcher** in `crates/nearsc/src/rules/<id>.rs`, registered in a static registry.

A parity test enforces that every TOML has a matcher and every matcher has a TOML entry. The KB and the MCP pattern lookup read the same TOML files, so documentation cannot drift from detection.

### Rule quality bar

1. **One behavior per fixture.** `vuln.rs` must emit exactly the rule id; `fixed.rs` must emit nothing.
2. **No false confidence.** Heuristic rules are labeled `heuristic`; spec-backed rules are labeled `spec`.
3. **Every finding has a fix.** The TOML `fixed` block is mandatory.
4. **Every finding has a reference.** NEAR docs, NEP, or public audit link.

## Finding model

See [RULES.md](RULES.md) for the JSON shape and the scan envelope. Findings are data, not prose: stable fields, no local paths in published examples.

## Reports

| Format | Use | Contract |
| --- | --- | --- |
| `text` | Terminal, humans | Table grouped by severity, summary line, exit code |
| `json` | Agents, scripts | Scan envelope, stable field names |
| `sarif` | GitHub code scanning, CI | SARIF 2.1.0, rule metadata from TOML |
| `html` | Screenshots, reports, demo | Single self-contained file, inline CSS, no JS |

## MCP server

Five tools over stdio: `nearsc_scan`, `nearsc_patterns`, `nearsc_audits`, `nearsc_contract_info`, `nearsc_poc_scaffold`. Full contracts in [MCP.md](MCP.md).

Design rules:

- Read-only. No tool writes to disk except `nearsc_poc_scaffold`, which returns file contents and never writes them itself.
- No shell execution. No secrets. No telemetry.
- Untrusted input: scanned repo text and KB content are data. Tool descriptions state this.
- Network only in `nearsc_contract_info` (public RPC, fixed endpoints).

## Knowledge base

`data/patterns/`, `data/audits/`, `data/postmortems/` with YAML frontmatter, plus `data/registry.json` (known contracts and audited code hashes) and a generated `data/index.json` for search. Embedded into the binary; updates ship as releases. Full schema in [KNOWLEDGE-BASE.md](KNOWLEDGE-BASE.md).

## Extension points

| Want to… | Do |
| --- | --- |
| Add a rule | TOML + matcher + fixtures + RULES.md entry ([CONTRIBUTING.md](CONTRIBUTING.md)) |
| Add a report format | Implement the renderer trait in `report/`, add a fixture |
| Add an MCP tool | Add a handler in `nearsc-mcp`, document in MCP.md, bump the tool list test |
| Add KB content | Frontmatter + source + confidence, rebuild index |

## Deliberate v0.1 simplifications

- No type inference or dataflow. Matchers use syntax + local context.
- No macro expansion. near-sdk attributes are read syntactically; body code is normal Rust.
- No incremental cache. Contracts are small; a full scan is fast.
- No parallel scanning. Determinism first; parallelism is a v0.2 concern.
