# Knowledge base

> **Status:** schema and sourcing rules for v0.1 (2026-11-09). Seed content is being gathered during the hackathon window; the index ships embedded in the binary.

## Purpose

A scanner tells you a pattern is present. Precedent tells you why it matters. The KB collects real NEAR audit reports, postmortems, and vulnerability classes so every finding can point to evidence instead of opinion.

## Layout

```
data/
├── patterns/       # NEAR vulnerability classes (one file per class)
├── audits/         # curated public audit reports (summary + source link)
├── postmortems/    # public incident postmortems (adjusted, sourced)
├── registry.json   # known contracts + audited code hashes
└── index.json      # generated search index (checked in)
```

## Entry schema

All entries use YAML frontmatter:

```yaml
---
title: "Callback hijack in a vault contract"
kind: pattern          # pattern | audit | postmortem
project: example       # optional for patterns
year: 2026
source: "https://..."  # required for audits and postmortems
retrieved: 2026-11-10  # required for audits and postmortems
confidence: verified-public   # verified-public | community | inferred
tags: [async, callbacks, access-control]
severity_counts: { critical: 0, high: 1, medium: 0, low: 2 }  # audits only
---
```

Body rules:

- **Patterns:** what the class is, how it manifests on NEAR, detection notes, a vulnerable and a fixed snippet, references.
- **Audits:** scope, what was found (summarized), which findings map to our rules, source link. Never paste the full third-party report unless its license allows it; summarize and link.
- **Postmortems:** timeline, root cause, the code pattern involved, what a scanner could have caught, source links.

## Confidence labels

| Label | Meaning |
| --- | --- |
| `verified-public` | Claim is traceable to a public source with a working link and retrieval date |
| `community` | Reported by a community member, not independently verified |
| `inferred` | Our analysis, clearly marked as such; never presented as a sourced fact |

The same vocabulary the ledger projects use. A missing record never proves absence.

## Sourcing rules

1. Public sources only. No client-confidential material, ever.
2. Every audit and postmortem entry has a source URL and a retrieval date.
3. Third-party text is summarized, not copied, unless the license permits verbatim reuse with attribution.
4. Corrections are welcome: open an issue with the entry path and the corrected claim.
5. No invented numbers. If a severity count is unknown, omit the field and say so in the body.

## Registry

`data/registry.json` maps known contract accounts to audited code hashes and audit links:

```json
{
  "wrap.near": {
    "label": "Wrapped NEAR (NEP-141)",
    "code_hash": "…",
    "audits": [ { "title": "…", "source": "…" } ],
    "verified_at": "2026-11-12"
  }
}
```

`nearsc_contract_info` compares the deployed code hash against this registry. A match means "this exact code was reviewed at some point", not "this contract is safe". The distinction is stated in every response.

## Index

`data/index.json` is a flat array generated from the frontmatter:

```json
{
  "id": "audits/burrowland",
  "kind": "audit",
  "title": "…",
  "project": "burrowland",
  "tags": ["lending", "promise-flows"],
  "severity": "high",
  "path": "data/audits/burrowland.md",
  "summary": "One paragraph.",
  "source": "https://…",
  "retrieved": "2026-11-10",
  "confidence": "verified-public"
}
```

The index is built by a small script and checked in, so the binary and CI are deterministic.

## Seed content for v0.1

- Patterns: the NEAR security classes from the v1 prompt stack (callbacks, 1-yocto, storage, reentrancy in the async model, randomness, front-running, sybil), rewritten as standalone notes.
- Audits: burrowland, linear-protocol, sputnikdao2 (summaries + links), plus public reports gathered this week.
- Postmortems: the NEAR Intents deposit-notification exploit (adjusted for public release, public sources only).
- Registry: 3–5 well-known contracts with verified code hashes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). A KB entry without a source and a confidence label is not accepted.
