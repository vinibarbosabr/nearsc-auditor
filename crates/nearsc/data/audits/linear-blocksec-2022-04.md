---
title: "LiNEAR audit, BlockSec, April 2022"
kind: audit
project: linear-protocol
year: 2022
source: "https://github.com/linear-protocol/audits/blob/main/BlockSec%20-%20Security%20Audit%20Report%20for%20LiNEAR%20-%20202204.pdf"
retrieved: 2026-11-09
confidence: verified-public
tags: [liquid-staking, defi, unbounded-iteration, unchecked-promise-results, privileged-setter-unguarded, precision]
summary: "BlockSec's LiNEAR liquid-staking audit: precision loss, locked balances, unlimited beneficiary reward distribution, and staking-request liveness, plus recommendations on gas checks and centralization. Findings classified per D-017."
---

# LiNEAR audit, BlockSec, April 2022

**Scope:** `linear-protocol/LiNEAR` (MIT), liquid staking contract (versions 1
and 2). Public report dated Apr 2022.

## Findings

| ID | Severity | Category | Finding | Vector |
| --- | --- | --- | --- | --- |
| LIN-1 | - | Software security | **Precision loss** in share/amount conversion: rounding direction must favor the protocol, otherwise value leaks across users on every conversion | `uncategorized` (arithmetic/precision class) |
| LIN-2 | - | DeFi security | **User's available balance may be locked temporarily**: interacting with the contract directly can leave `unstaked` balances stuck behind the UI flow | `uncategorized` (state accessibility) |
| LIN-3 | - | DeFi security | **Unlimited reward distribution to beneficiaries**: reward accounting scales with the beneficiary set; unbounded sets make epoch updates fragile | `unbounded-iteration` (NS007) |
| LIN-4 | - | DeFi security | **Unstaking requests may not be satisfied in time**: liveness depends on validator liquidity and request ordering | `uncategorized` (liveness) |

Additional recommendations (as filed): `epoch_update_rewards` may not work
with unlimited beneficiaries (gas / unbounded iteration); redundant code;
missing `prepaid_gas` check in `ft_transfer_call` (the receiver needs enough
gas for its `ft_on_transfer`, or the transfer resolves as a refund);
centralized design risk around owner/manager keys, recommend multi-sig.

The report does not publish a severity table for these items (advisory-style
categories); severity_counts is omitted per the no-invented-numbers rule.

## Why it matters for nearsc

- The `prepaid_gas` recommendation is the NEP-141 `ft_transfer_call` failure
  class that nearsc documents under NS004/NS011: gas shortfalls resolve as
  refunds, and the caller must handle that outcome.
- The unlimited-beneficiary finding is the unbounded-iteration pattern (NS007)
  in a production staking contract.
- LIN-1 (rounding direction) pairs with the same class found in the Potlock
  audit (GUV-4): fee/share math must round against the user.

## Source

Summarized from the public BlockSec report:
<https://github.com/linear-protocol/audits/blob/main/BlockSec%20-%20Security%20Audit%20Report%20for%20LiNEAR%20-%20202204.pdf>.
This entry is summary-depth (D-017): findings classified, no per-finding
blocks; upgrade to blocks is v0.2 polish.
