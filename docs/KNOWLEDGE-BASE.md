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

## Entry depth (D-017)

Audit and postmortem entries ship at one of three depths:

| Depth | What ships | Where the full text lives |
| --- | --- | --- |
| Catalogued | scope + findings table + severity counts | this repo |
| Curated | + per-finding blocks (issue, where + commit-pinned permalink, quoted code, impact, fix, vector + rule classification) | this repo |
| Transcribed | + full faithful transcript | maintainer's research vault, not this repo (license + size) |

Full transcripts are never published here: third-party reports are summarized and linked per
the license rules below, and the embedded binary stays small (D-011). Findings are classified
against the pattern catalogue (`data/patterns/`); unclassified findings are marked
`uncategorized` with a note on the missing class. Code excerpts are quoted from the audited
project's own repository at the audited commit (commit-pinned permalink) when its license
permits (MIT, Apache-2.0), with attribution; otherwise the entry is paraphrase-only. The
first entries in the classified format: [potlock-guvenkaya-2024-01](../data/audits/potlock-guvenkaya-2024-01.md)
(transcribed + curated) and [near-intents-guvenkaya-2025-02](../data/audits/near-intents-guvenkaya-2025-02.md)
(curated, paraphrase-only because no public upstream repo was locatable).

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

- Patterns: 15 NEAR security classes (the v1 classes rewritten as standalone notes, plus
  storage-griefing and sybil resistance), each now carrying a `## Precedent` section linking
  the audit entries that exhibit the class.
- Audits (6 shipped): burrowland x2 (BlockSec 2022, pre-D-017 summary depth), linear x2
  (BlockSec 2022, Hacken 2024, pre-D-017 summary depth), sputnikdao2 storage-withdraw issue
  (2026, pre-D-017 summary depth), potlock (Guvenkaya 2024, transcribed + classified per
  D-017), near-intents (Guvenkaya 2025, curated, classified, paraphrase-only). The KB backlog
  (maintainer's vault) holds ~57 unique public audits for catalogue expansion (D-017).
- Postmortems (2 shipped): NEAR Intents deposit-notification exploit (Oct 2026) and RHEA
  margin-trading slippage exploit (Apr 2026).
- Registry: seeded 2026-11-12 - `contract.main.burrow.near`, `intents.near`,
  `v2.ref-finance.near`, each backed by shipped entries with honest coverage caveats.

**Registry footing (D-008, amended 2026-11-12 in the D-017 KB session):** the registry shipped empty at v0.1 scaffold and was seeded on 2026-11-12 with `contract.main.burrow.near`, `intents.near`, and `v2.ref-finance.near` - `code_hash` from live RPC only, every entry backed by a shipped audit/postmortem entry, with honest coverage caveats written into the audits list labels (e.g. the Ref entry points at the catalogued-but-pending 2022 BlockSec reports). Entries get seeded only where a shipped public entry can back them. The RPC lookup (`nearsc contract`) and the `nearsc_contract_info` tool work regardless and report unregistered accounts as such.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). A KB entry without a source and a confidence label is not accepted.
