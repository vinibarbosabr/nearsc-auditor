---
title: "Burrow re-audit, BlockSec, March 2022"
kind: audit
project: burrowland
year: 2022
source: "https://github.com/NearDeFi/burrowland/blob/main/blocksec-audit-signed-2.pdf"
retrieved: 2026-11-09
confidence: verified-public
tags: [lending, defi, storage-griefing, unbounded-iteration, privileged-setter-unguarded, remediation]
summary: "BlockSec's follow-up Burrow review after the February fixes: seven findings across software and DeFi security, all fixed in the audited commits. Findings classified per D-017."
---

# Burrow re-audit, BlockSec, March 2022

**Scope:** `NearDeFi/burrowland`, audited commits `0de39e9` (initial) and
`3ff104c` (version 1.0), with fixes verified at `6fe609b`. Public report dated
Mar 19, 2022.

## Findings (all fixed)

| ID | Severity | Finding | Status | Vector |
| --- | --- | --- | --- | --- |
| BUR-1 | Medium | `MAX_NUM_ASSETS` cannot be changed without a contract upgrade | Fixed | `uncategorized` (asset-config limit; manifest-level) |
| BUR-2 | Medium | Missing check on the returned value of `shares_to_amount` (can exceed the pool balance) | Fixed | `uncategorized` (share/amount conversion; arithmetic/precision class) |
| BUR-3 | Medium | Storage usage is wrong in the liquidation action (double counting the liquidation account's bytes) | Fixed | `storage-griefing` (NS008) |
| BUR-4 | Medium | Storage usage is wrong when setting a user's storage (contract-wide `storage_usage()` compared against a per-account baseline) | Fixed | `storage-griefing` (NS008) |
| BUR-5 | Medium | Incomplete asset configuration check in `update_asset` (mutable fields that must be immutable, unvalidated ranges) | Fixed | `uncategorized` (validation) |
| BUR-6 | Medium | `PriceData` freshness is not checked before use | Fixed | `uncategorized` (stale oracle data) |
| BUR-7 | Medium | Configuration is not validated in the `init` function (added in this follow-up) | Fixed | `init-ignore-state-guard` (NS005-adjacent: init-time validation) |

## Why it matters for nearsc

- Confirms the storage-accounting class (NS008) as the dominant finding type in
  a production NEAR lending contract (BUR-3/BUR-4).
- BUR-7 lands on the init-guard class nearsc encodes as NS005: init must
  validate its configuration, since `#[init]` runs once and replaces state.
- The re-audit pattern (same findings re-checked against fix commits) is what
  the `hackathon-submission` diff will look like: scanner findings are only
  useful if each one maps to a verifiable code location.

## Source

Summarized from the public BlockSec report:
<https://github.com/NearDeFi/burrowland/blob/main/blocksec-audit-signed-2.pdf>.
This entry is summary-depth (D-017): findings classified, no per-finding
blocks; upgrade to blocks is v0.2 polish.
