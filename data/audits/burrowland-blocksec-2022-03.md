---
title: "Burrow re-audit, BlockSec, March 2022"
kind: audit
project: burrowland
year: 2022
source: "https://github.com/NearDeFi/burrowland/blob/main/blocksec-audit-signed-2.pdf"
retrieved: 2026-11-09
confidence: verified-public
tags: [lending, defi, storage-accounting, remediation]
summary: "BlockSec's follow-up Burrow review after the February fixes: seven findings across software and DeFi security, all fixed in the audited commits."
---

# Burrow re-audit, BlockSec, March 2022

**Scope:** `NearDeFi/burrowland`, audited commits `0de39e9` (initial) and
`3ff104c` (version 1.0), with fixes verified at `6fe609b`. Public report dated
Mar 19, 2022.

## Findings (all fixed)

1. `MAX_NUM_ASSETS` cannot be changed without a contract upgrade.
2. Missing check on the returned value of `shares_to_amount` (can exceed the
   pool balance).
3. Storage usage is wrong in the liquidation action (double counting the
   liquidation account's bytes).
4. Storage usage is wrong when setting a user's storage (contract-wide
   `storage_usage()` compared against a per-account baseline).
5. Incomplete asset configuration check in `update_asset` (mutable fields that
   must be immutable, unvalidated ranges).
6. `PriceData` freshness is not checked before use.
7. Configuration is not validated in the `init` function (added in this
   follow-up).

## Why it matters for nearsc

- Confirms the storage-accounting class (NS008) as the dominant finding type in
  a production NEAR lending contract.
- The re-audit pattern (same findings re-checked against fix commits) is what
  the `hackathon-submission` diff will look like: scanner findings are only
  useful if each one maps to a verifiable code location.

## Source

Summarized from the public BlockSec report:
<https://github.com/NearDeFi/burrowland/blob/main/blocksec-audit-signed-2.pdf>.
