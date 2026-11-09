---
title: "LiNEAR audit, BlockSec, April 2022"
kind: audit
project: linear-protocol
year: 2022
source: "https://github.com/linear-protocol/audits/blob/main/BlockSec%20-%20Security%20Audit%20Report%20for%20LiNEAR%20-%20202204.pdf"
retrieved: 2026-11-09
confidence: verified-public
tags: [liquid-staking, defi, precision, gas, rewards]
summary: "BlockSec's LiNEAR liquid-staking audit: precision loss, locked balances, unlimited beneficiary reward distribution, and staking-request liveness, plus recommendations on gas checks and centralization."
---

# LiNEAR audit, BlockSec, April 2022

**Scope:** `linear-protocol/LiNEAR`, liquid staking contract (versions 1 and 2).
Public report dated Apr 2022.

## Software security

1. **Precision loss** in share/amount conversion: rounding direction must favor
   the protocol, otherwise value leaks across users on every conversion.

## DeFi security

1. **User's available balance may be locked temporarily**: interacting with the
   contract directly can leave `unstaked` balances stuck behind the UI flow.
2. **Unlimited reward distribution to beneficiaries**: reward accounting scales
   with the beneficiary set; unbounded sets make epoch updates fragile.
3. **Unstaking requests may not be satisfied in time**: liveness depends on
   validator liquidity and request ordering.

## Additional recommendations

- `epoch_update_rewards` may not work with unlimited beneficiaries (gas /
  unbounded iteration).
- Redundant code.
- Missing `prepaid_gas` check in `ft_transfer_call` (the receiver needs enough
  gas for its `ft_on_transfer`, or the transfer resolves as a refund).
- Centralized design risk around owner/manager keys; recommend multi-sig.

## Why it matters for nearsc

- The `prepaid_gas` finding is the NEP-141 `ft_transfer_call` failure class that
  nearsc documents under NS004/NS011: gas shortfalls resolve as refunds, and the
  caller must handle that outcome.
- The unlimited-beneficiary finding is the unbounded-iteration pattern (NS007)
  in a production staking contract.

## Source

Summarized from the public BlockSec report:
<https://github.com/linear-protocol/audits/blob/main/BlockSec%20-%20Security%20Audit%20Report%20for%20LiNEAR%20-%20202204.pdf>.
