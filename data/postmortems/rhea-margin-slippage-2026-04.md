---
title: "RHEA Finance margin-trading slippage exploit (16 Apr 2026)"
kind: postmortem
project: rhea-finance
year: 2026
source: "https://x.com/rhea_finance/status/2045203607856042118"
retrieved: 2026-11-12
confidence: verified-public
tags: [lending, defi, slippage, oracle-manipulation, margin-trading, min-amount-out]
summary: "Burrow/RHEA margin trading summed min_amount_out across swap actions without accounting for intermediary token reuse between steps; an attacker routed borrowed debt through self-built fake-token Ref pools, drained $18.4M from the reserve pool, then staged liquidations. Partial recovery (funds returned/frozen); lending contract frozen during recovery."
---

# RHEA Finance margin-trading slippage exploit (16 Apr 2026)

| Field | Value |
|---|---|
| Incident date | 16 Apr 2026, 08:22-09:42 UTC (exploit window) |
| Staging | 13-16 Apr 2026 (attacker accounts, fake pools, router) |
| Target | RHEA Finance Lending Market (previously Burrow Finance), margin trading feature |
| Loss | ~$18.4M drained from the protocol reserve pool |
| Recovery (at disclosure) | 3.359M USDC + 1.564M NEAR returned to the lending contract; 4.34M USDT frozen (3.291M frozen by Tether, 1.053M in NEAR Intents); lending contract frozen to preserve funds |
| Attack class | Cross-action slippage aggregation flaw (min_amount_out summed across swap steps, ignoring intermediary token reuse) |
| Root cause (preliminary, official) | slippage protection in the margin-trading execution path did not account for swap steps whose output token is reused as the next step's input |
| Affected code | `burrowland/margin_trading.rs#L102` (official citation) |
| Example attack tx | `44tWhQmmkTJgchgFVkYpPrgyKvaH7wRLu1jZWXD3Du1x` |
| Primary source | [RHEA Finance incident report, 17 Apr 2026](https://x.com/rhea_finance/status/2045203607856042118) |

Independent KB entry prepared from the official disclosure; on-chain
attribution is probabilistic per the report itself and is recorded as
reported, not verified.

## 1. Executive summary

On 16 April 2026 the RHEA (ex-Burrow) lending market's margin-trading feature was exploited
through its slippage protection: the protection summed the `min_amount_out` values of all swap
actions in a chain to derive one expected final output, but did not account for steps whose
output token is reused as the input of the next step. The attacker spent the staging days
building purpose-made fake-token pools on Ref Finance at controlled prices and a swap router
through them, then opened a large batch of margin positions whose swap routes passed through
those pools. The borrowed debt tokens flowed into attacker-owned pools while only a negligible
amount of position token returned to the protocol, yet the aggregated `min_amount_out` check
passed. Each position was worth far less than its debt and triggered immediate forced
liquidations; the cascade depleted the protocol's reserve pool (~$18.4M) and the attacker
extracted the value from the fake pools. Partial recovery followed (funds returned, frozen, CEX
trace opened).

## 2. Root cause (official, preliminary)

The margin-trading execution path aggregated slippage protection incorrectly:

> The algorithm summed all min_amount_out values across swap actions to derive a final expected
> output, but it did not account for swap actions where the output token of one step is reused
> as the input of the next.

Consequence: the real token output reaching the protocol could be far below what the slippage
guarantee appeared to require, while the check itself passed. The report states the issue
appears specific to the margin-trading execution path and flags that other contributing factors
may surface as the investigation continues. Affected code cited: `burrowland/margin_trading.rs#L102`.

## 3. Attack path (official chronology, condensed)

1. **Staging (13-16 Apr).** Attacker MCA accounts activate (first action: `storage_deposit`
   on `lst.rhealab.near`, 14 Apr 03:49 UTC). A dust-funded implicit "subject wallet" is created
   15 Apr 06:53 and funded from `intents.near` (attacker onboarding capital from another chain);
   no direct transfer ever connects any Rhea contract to the subject wallet. ~71,000 NEAR are
   wrapped and distributed to dozens of implicit accounts (423 unique counterparties over
   15-16 Apr).
2. **Fake market construction (15 Apr 22:08-22:49 UTC).** On `v2.ref-finance.near`: 8
   `add_simple_pool` calls create pools pairing purpose-built fake token contracts with
   USDC/USDT/wNEAR/ZEC (pool IDs 8528-8538); `add_liquidity` seeds artificial price ratios; a
   swap router through the fake pools is built as the attack vector. The fake token contracts
   (implicit addresses, no NEP-141 metadata methods) were purpose-built for price manipulation.
   ~21 intermediary accounts deleted in ~30s (22:48-22:49), subject wallet as sole beneficiary.
3. **Exploit (16 Apr 08:22-09:42 UTC).** The attacker opens a large number of margin positions
   with swap routes through the fake pools; slippage aggregation passes; debt tokens divert to
   attacker pools; negligible position token reaches the protocol; immediate forced liquidations
   cascade; the reserve pool is depleted (~$18.4M); liquidity is removed and value extracted.
   During the window, the hub contract (`get_owner()` = subject wallet) moves funds; refund
   addresses on ETH and ZEC were published in the report; on NEAR the funds went to
   `contract.main.burrow.near` (the RHEA lending contract). 55 intermediary accounts total were
   deleted across three waves with the subject wallet as beneficiary.
4. **Mitigation.** Affected contracts paused immediately; authorities notified; a security team
   engaged for forensics; recovery framework funded from the protocol reserve.

## 4. What a scanner could have caught

Nothing deterministic at v0.1, honestly:

- The flaw is cross-action value-flow reasoning (token produced by step N is consumed by step
  N+1, so per-action `min_amount_out` values are not additive) - dataflow/semantic analysis
  beyond any single-site AST rule, and beyond nearsc's v0.1 scope (promise-flow dataflow is a
  v0.2 roadmap item; this would need a full swap-graph analysis).
- The manipulation surface (fresh Ref pools at artificial prices feeding an on-chain price
  oracle) is the oracle-manipulation class: the KB's frontrunning/sybil pattern notes touch it;
  no nearsc rule covers price-oracle trust. Candidate v0.2 class: "fresh-pool / low-liquidity
  oracle inputs" and "min_amount_out aggregation across multi-hop routes".
- What a reviewer (or a future rule) can flag generically: privileged/aggregated execution
  paths that compose unbounded user-supplied action arrays (see
  [arbitrary-promise-target](../patterns/arbitrary-promise-target.md) for the adjacent class),
  and liquidation cascades triggered by under-collateralized positions.

## 5. Lessons for NEAR builders

- Slippage protection must be evaluated per net flow, not summed per action when tokens are
  reused across steps; multi-hop routes need end-to-end invariants (final received amount vs
  total debt), not per-leg minimums.
- Any path that lets a position's swap route be chosen by the position opener is a
  price-manipulation surface: constrain routes to vetted pools or enforce liquidity/age
  requirements on pool inputs to oracles.
- Value flows across a batch of user-supplied actions need the same adversarial treatment as
  cross-contract promise chains: assume each intermediate value can be steered.

## 6. Related KB entries

- Audits of the same project: [Burrow audit, BlockSec, February 2022](../audits/burrowland-blocksec-2022-02.md),
  [Burrow re-audit, BlockSec, March 2022](../audits/burrowland-blocksec-2022-03.md) (neither
  covers margin trading - the exploited feature post-dates both reports).
- Patterns: [arbitrary-promise-target](../patterns/arbitrary-promise-target.md) (user-steered
  execution targets), [frontrunning](../patterns/frontrunning.md) (ordering/oracle trust).
- Ecosystem postmortem family: [NEAR Intents deposit-notification exploit](near-intents-deposit-notification-2026-10.md)
  (the attacker's capital was onboarded through `intents.near`; NEAR Intents also held
  1.053M USDT of the frozen funds).

## 7. Sources

Primary: [RHEA Finance Protocol Incident (X article, 17 Apr 2026)](https://x.com/rhea_finance/status/2045203607856042118).
Official follow-ups in the same thread (identification and return-the-funds demands) are not
part of this entry's factual basis. All figures and chronology are the report's own; the report
labels its analysis preliminary and its attribution probabilistic.

unverified: post-disclosure recovery updates - the report is a point-in-time disclosure;
later recovery developments after 17 Apr 2026 are not tracked in this entry.
