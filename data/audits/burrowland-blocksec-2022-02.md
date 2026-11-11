---
title: "Burrow audit, BlockSec, February 2022"
kind: audit
project: burrowland
year: 2022
source: "https://github.com/NearDeFi/burrowland/blob/main/blocksec-audit-signed-1.pdf"
retrieved: 2026-11-09
confidence: verified-public
severity_counts: {"critical":0,"high":0,"medium":5,"low":1}
tags: [lending, defi, storage-griefing, unbounded-iteration, one-yocto-transfer-auth, privileged-setter-unguarded, storage-accounting, oracle]
summary: "BlockSec's first Burrow audit (6 issues: 5 medium, 1 low, plus 7 recommendations, all fixed). Storage accounting in liquidation and per-account storage updates is the recurring theme. Findings classified per D-017."
---

# Burrow audit, BlockSec, February 2022

**Scope:** `NearDeFi/burrowland` (Unlicense-licensed; repo archived 2023), the
`contract` directory: collateral and borrowed asset management, liquidations,
storage accounting, oracle price consumption. Public report dated Feb 14, 2022.

## Findings

| ID | Severity | Finding | Status | Vector |
| --- | --- | --- | --- | --- |
| BUR-1 | Medium | `MAX_NUM_ASSETS` is a constant; adding assets can fail the assert | Fixed | `uncategorized` (asset-config limit; manifest-level) |
| BUR-2 | Medium | `shares_to_amount` can return more than the pool balance | Fixed | `uncategorized` (share/amount conversion; arithmetic/precision class) |
| BUR-3 | Medium | Storage usage is computed wrong in the liquidation action | Fixed | `storage-griefing` (NS008) |
| BUR-4 | Medium | Storage usage is computed wrong in per-account storage updates | Fixed | `storage-griefing` (NS008) |
| BUR-5 | Low | Incomplete asset configuration check | Fixed | `uncategorized` (validation) |
| BUR-6 | Medium | `PriceData` freshness is not checked | Fixed | `uncategorized` (stale oracle data; no pattern file yet) |

Seven recommendations were also filed (dead code, deflation-token support,
redundant calls, oracle reliability, upgrade module, centralization risk,
allowed actions).

## Why it matters for nearsc

- Findings BUR-3/BUR-4 are the storage-accounting class nearsc tracks as NS008:
  `env::storage_usage()` is contract-wide, so per-account ledger math must
  snapshot before/after, not compare against a global value.
- BUR-6 is a freshness check: consuming stale oracle prices is a
  correctness bug that static rules can only flag heuristically.
- The report shows the review style nearsc targets: DeFi accounting plus NEAR
  storage semantics, not generic Rust linting.

## Source

Summarized from the public BlockSec report:
<https://github.com/NearDeFi/burrowland/blob/main/blocksec-audit-signed-1.pdf>.
See the report for full detail and code excerpts. This entry is
summary-depth (D-017): findings classified, no per-finding blocks; upgrade
to blocks is v0.2 polish.
