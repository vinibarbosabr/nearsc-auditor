---
title: "NEAR Intents deposit-notification exploit (1 Oct 2026)"
kind: postmortem
project: near-intents
year: 2026
source: "https://x.com/AlexAuroraDev/status/2111124226962870770"
retrieved: 2026-11-09
confidence: verified-public
tags: [async, callbacks, ledger-accounting, defi, bridge]
summary: "An attacker failed the notification leg of ft_transfer_call deposits; the FT contract refunded the tokens while the Intents Verifier kept the internal credit, minting $3.8M in ghost balances that were withdrawn through Omni. All funds were recovered; the feature was removed."
---

# NEAR Intents Deposit-Notification Exploit (1 Oct 2026)

| Field | Value |
|---|---|
| Incident date | 29 Sep - 1 Oct 2026 (withdrawal window) |
| Detection | 1 Oct 2026, 08:04 (all times from official postmortem, timezone unspecified) |
| Target | `intents.near` (NEAR Intents "Verifier" / defuse smart contract) |
| Loss | $3.8M ghost funds minted; 100% recovered within 36h of detection |
| Attack class | Async callback accounting inconsistency (credit/rollback gap across promise chain) |
| Affected feature | Deposit notifications (`DepositAction::Notify`) in `ft_on_transfer` / `nft_on_transfer` / `mt_on_transfer` |
| Root cause | Internal ledger credit in `ft_on_transfer` not reverted when the attacker-controlled notification leg failed and the FT contract refunded the tokens |
| Fix | Hotfix deployed 2 Oct; feature removed entirely 7 Oct (PR [#374](https://github.com/near/intents/pull/374)) |
| Primary source | [Official postmortem by Alex Shevchenko](https://x.com/AlexAuroraDev/status/2111124226962870770) |

Independent postmortem prepared from the official report, the public `near/intents` repository history, and NEAR protocol documentation. Marketing and community content removed. Reconstruction labeled where the official report does not specify exact mechanics.

## 1. Executive summary

The NEAR Intents Verifier contract (`intents.near`) credited user deposits to its internal ledger synchronously inside `ft_on_transfer`, while the actual finality of the token transfer depended on an asynchronous promise chain ending in a resolve callback (`ft_resolve_deposit`). An attacker deployed a contract designed to fail the notification leg of that chain. The NEP-141 token contract then refunded the deposited tokens to the attacker, but the Verifier's internal ledger kept the credit. After 23 such deposits, the attacker held $3.8M in ghost internal balance, which they withdrew as real tokens through the Omni bridge, since the withdrawal was below the contract's real holdings. Monitoring did not reconcile internal user balances against the contract's on-chain token balance, so the attack ran for days before detection. All funds were recovered; the feature was later removed entirely.

## 2. Target architecture

- **NEAR Intents**: multichain intents protocol. Users deposit tokens, express intents (swaps, transfers), and solvers fulfill them. Settlement happens in the Verifier contract on NEAR.
- **Verifier / defuse**: the main contract in [`contracts/defuse`](https://github.com/near/intents/tree/main/contracts/defuse) of the `near/intents` repo, deployed at `intents.near` ([nearblocks](https://nearblocks.io/address/intents.near)). "defuse" is the legacy name being phased out.
- **Omni infrastructure**: bridges funds to NEAR (PoA bridge; separate `poa` contracts in the repo). Official postmortem: the bug was in the Intents contract, **not** in Omni.
- **Three balances per asset** (per official postmortem):
  1. Tokens on the origin (foreign) chain, held by bridge treasuries: total `X`.
  2. NEAR-side NEP-141 token contracts: total supply `X`.
  3. Tokens actually held by the Intents contract: `Y < X` (other NEAR accounts hold the rest).
- **Internal ledger**: the Verifier tracks per-user balances internally (multi-token style). The invariant that must hold: sum of all internal user balances <= `ft_balance_of(intents.near)` per token. This invariant was not monitored and was violated by the attack.

Key NEAR runtime property enabling the bug: execution is asynchronous and receipt-based. A `ft_transfer_call` splits into: token transfer + `ft_on_transfer` on the receiver, then the receiver's returned promise resolves, then the FT contract's private `ft_resolve_transfer` finalizes refunds. Any contract composition across those steps must handle failure of every intermediate call, including out-of-gas. See [Token transfer flow](https://docs.near.org/protocol/data-flow/token-transfer-flow.md) and the [FT implementation security guide](https://docs.near.org/smart-contracts/security/cross-contract-calls/ft-transfer-call.md).

## 3. Root cause

The deposit-notification feature let a depositor attach a `Notify` action to a deposit, causing the Verifier to call an arbitrary third-party contract on NEAR during the deposit (a "deposit notification" to the recipient).

Reconstructed vulnerable flow in `contracts/defuse/src/contract/tokens/nep141/deposit.rs` (pre-#374 code, quoted from the [PR #374 diff](https://github.com/near/intents/pull/374.diff)):

```rust
// 1. Internal ledger credit happens synchronously in ft_on_transfer:
self.deposit(
    receiver_id.clone(),
    [(token_id.clone(), amount.0)],
    Some("deposit"),
)
.unwrap_or_else(|err| err.panic());

// 2. ...then the async notification leg is kicked off:
DepositAction::Notify(notify) => Self::notify_on_transfer(
    sender_id.clone(),
    vec![sender_id],
    receiver_id.clone(),          // attacker-controlled notify target
    vec![token_id.to_string()],
    vec![amount],
    notify,
)
.unwrap_or_else(|err| err.panic())
.then(
    Self::ext(env::current_account_id())
        .with_static_gas(Self::mt_resolve_deposit_gas(1))
        .with_unused_gas_weight(0)
        .ft_resolve_deposit(receiver_id, env::predecessor_account_id(), amount),
)
.into(),
```

The credit (step 1) and the definitive token movement (step 2's resolution, plus the FT contract's own `ft_resolve_transfer`) live in different async steps. The official postmortem describes the failure mode:

> the attacker created a contract on NEAR Protocol that was failing these notification calls, which led to the token contract returning deposited funds, while the NEAR Intents contract was keeping the recorded deposit.

Under NEP-141 semantics, a failed receiver call resolves to a full refund of the transferred amount ([ft-transfer-call security guide](https://docs.near.org/smart-contracts/security/cross-contract-calls/ft-transfer-call.md): "requested_refund = ft_on_transfer result, or amount if the call failed"). The Verifier's rollback path (`ft_resolve_deposit`) failed to keep the internal ledger consistent with that outcome: tokens left the contract (refunded to the attacker), the internal credit stayed.

**Exact sub-mechanism not publicly specified.** The official report does not state whether the rollback callback mis-accounted, silently swallowed the failure, or starved on static gas. Circumstantial evidence for the gas-starvation hypothesis exists in the fix itself (all resolve-callback gas constants were raised, see section 7), and PR [#367](https://github.com/near/intents/pull/367) (2 Oct) changed notification errors to be "reported instead of being silently ignored". Unconfirmed; treat as open question.

This is a documented NEAR bug class: the official docs warn that bugs live "in the gap between" the steps of `ft_on_transfer` / `ft_resolve_transfer` compositions, and the postmortem itself says the feature "had a history of bug reports, all in the gap between its two steps".

## 4. Attack path (reconstructed)

1. **Preparation**: attacker creates an account and a contract on NEAR designed so that calls into it fail (panic or gas exhaustion) when invoked as a deposit-notification receiver.
2. **Ghost-fund minting** (per official postmortem, performed over multiple days, 23 transactions total):
   1. Attacker calls `ft_transfer_call` on a NEP-141 token, receiver `intents.near`, with a `DepositMessage` JSON containing a `Notify` action whose target is the attacker's malicious contract.
   2. Token contract transfers tokens to `intents.near` and invokes `ft_on_transfer`.
   3. Verifier credits attacker's internal balance (the `deposit(...)` call above).
   4. Verifier calls the attacker's contract (notification leg); the call fails.
   5. Token contract's `ft_resolve_transfer` refunds the deposited tokens to the attacker (full refund on failed receiver call).
   6. Verifier's internal ledger keeps the credit: attacker now holds ghost balance backed by nothing.
3. **Net effect after 23 iterations**: internal ledger total = `Y + $3.8M`; actual contract holdings = `Y`. Attacker's internal account = `$3.8M` of it. Solvency invariant broken with no alarm.
4. **Exit** (29 Sep 16:14 - 1 Oct 05:54): attacker withdraws $3.8M of internal balance. Since $3.8M < `Y`, the contract's real holdings cover it; the withdrawal executes normally and the Omni infrastructure moves real assets to a foreign chain. Nothing about the exit transaction itself is invalid; the theft was fully realized at deposit time.
5. **Victims**: remaining users of the affected tokens (contract now under-collateralized); made whole after recovery.

## 5. Affected code

All paths relative to [near/intents](https://github.com/near/intents) `main` at time of writing:

| File | Role |
|---|---|
| `contracts/defuse/src/contract/tokens/nep141/deposit.rs` | FT deposit entry (`ft_on_transfer`); credit + Notify leg (removed by #374) |
| `contracts/defuse/src/contract/tokens/nep171/deposit.rs` | NFT deposit entry; same pattern (removed by #374) |
| `contracts/defuse/src/contract/tokens/nep245/deposit.rs` | Multi-token deposit entry; same pattern (removed by #374) |
| `contracts/defuse/src/tokens/mod.rs` | `DepositAction` enum; `Notify(NotifyOnTransfer)` variant commented out by #374 |
| `contracts/defuse/src/contract/tokens/mod.rs` | `mt_resolve_deposit_gas`, `resolve_deposit_internal`; gas helper commented out by #374 |
| `contracts/defuse/src/contract/tokens/nep141/withdraw.rs`, `nep171/withdraw.rs`, `nep245/core.rs`, `nep245/withdraw.rs` | Resolve/withdraw gas constants (raised by #374) |

## 6. Detection failure and response

- **What monitoring covered**: discrepancy between origin-chain treasury balances and total NEAR-side token supply (`X` vs `X`). Both stayed consistent; the attack did not touch that pair.
- **What it missed**: sum of internal user balances vs the contract's own token balance (`Y`-side invariant). This allowed 23 faulty deposits across multiple days and a ~37.7h withdrawal window (29 Sep 16:14 to 1 Oct 05:54) before human detection.
- **Response speed once detected**: 2h10m from last withdrawal to problem identification (08:04), contract paused by 08:33, frontend in maintenance by 08:40.
- **Recovery**: 100% of funds returned 2 Oct after investigation and negotiation with the attacker (SHIELD, chain analysis, external researchers). No details on negotiation terms were published.

## 7. Timeline (official report fused with repository history)

| Time (2026) | Event | Source |
|---|---|---|
| 13-15 Jan | Bug bounty report on a similar third-party-call feature; fixed on mainnet in 2 days; not exploited | Official |
| Jan - Mar | Additional security hardening merged to `main` | Official |
| 24 Sep, 12:09 UTC | PR [#354](https://github.com/near/intents/pull/354) `feat: arbitrary call` merged (pre-incident context) | Git |
| 29 Sep 16:14 - 1 Oct 05:54 | Attacker withdraws $3.8M via Omni | Official |
| 1 Oct 08:04 | Withdrawal problems identified | Official |
| 1 Oct 08:33 | `intents.near` paused | Official |
| 1 Oct 08:40 | near.com in maintenance mode | Official |
| 1 Oct 19:03 UTC | PR [#361](https://github.com/near/intents/pull/361) merged: notifications no longer accept `state_init` data | Git |
| 1 Oct 20:41 UTC | PR [#363](https://github.com/near/intents/pull/363) merged: auth toggle fix | Git |
| 1 Oct 20:57 UTC | PR [#364](https://github.com/near/intents/pull/364) merged: batch token limits | Git |
| 1 Oct 21:29 UTC | PR [#365](https://github.com/near/intents/pull/365) merged: release `defuse/v0.4.3` (commit [`cbe714b`](https://github.com/near/intents/commit/cbe714b331d9565426dfa2c3affd2584c0f1e4a1)) | Git |
| 1 Oct 11:20 / 14:00 | Contract unpaused (affected routes stay paused); near.com restored | Official |
| 2 Oct 12:50 UTC | PR [#367](https://github.com/near/intents/pull/367) merged: notification errors now reported instead of silently ignored; token-count limits on notification processing | Git |
| 2 Oct 12:55 UTC | PR [#368](https://github.com/near/intents/pull/368) merged: release `defuse/v0.4.4` (commit [`a2dd140`](https://github.com/near/intents/commit/a2dd140892b68140bf7e70814604d3ba074d656c)) | Git |
| 2 Oct 20:31 | Fix deployed on mainnet (consistent with the v0.4.4 release window; exact release-to-deploy mapping not officially confirmed) | Official + Git |
| 2 Oct 20:38 | Deposits unpaused | Official |
| 2 Oct | All funds returned | Official |
| 7 Oct | Second critical bug reported in the same feature (researcher @rohanganapa via bug bounty; $300k award) | Official |
| 7 Oct 17:51 UTC | PR [#374](https://github.com/near/intents/pull/374) merged (commit [`16d04f6`](https://github.com/near/intents/commit/16d04f6ec4401263f8914638710260da50bb46b0)): deposit notifications removed entirely, `defuse/v0.4.5` | Git |
| 16 Oct | Official postmortem published | Official |

Note: the specific commit for the January bounty fix was not identified in public history. Refund/notification-handling PRs from that window exist (e.g. [#198](https://github.com/near/intents/pull/198) `fix: check refund log length limits`, merged 29 Jan); attribution unconfirmed.

## 8. Deployed fixes

**Hotfix (2 Oct, v0.4.3/v0.4.4 window)**: PRs #361, #363, #364, #367; cumulative effect per #367's release notes: transfer notification errors surfaced instead of silently ignored, state-init removed from notifications, batch/token-count limits added. Official postmortem confirms a fix was live on mainnet 2 Oct 20:31.

**Feature removal (7 Oct, PR [#374](https://github.com/near/intents/pull/374), v0.4.5)**:

- `DepositAction::Notify` variant commented out in `contracts/defuse/src/tokens/mod.rs`; `Execute` deposits remain:

```rust
pub enum DepositAction {
    Execute(ExecuteIntents),
    // Notify(NotifyOnTransfer),
}
```

- Notify branches removed from all three deposit handlers (NEP-141/171/245); notification-specific resolve helpers (`mt_resolve_deposit_gas`) commented out.
- Resolve/withdraw callback gas raised across the board:
  - `FT_RESOLVE_WITHDRAW_GAS`: 5 -> 15 Tgas (`nep141/withdraw.rs`)
  - `NFT_RESOLVE_WITHDRAW_GAS`: 5 -> 15 Tgas (`nep171/withdraw.rs`)
  - `MT_RESOLVE_TRANSFER_*`: 2/8 -> 5/10 Tgas (`nep245/core.rs`)
  - `MT_RESOLVE_WITHDRAW_*`: 2/8 -> 5/10 Tgas (`nep245/withdraw.rs`)
- Matching integration tests commented out (`tests/src/tests/defuse/tokens/nep141.rs`, `nep171.rs`, `nep245/mod.rs`).

**Monitoring**: new invariant check, total internal user balances vs contract token balance; invariant failure triggers automatic contract pause.

**Programmatic**: bug bounty continues on HackenProof (up to $300k critical; both 2026 reports on this feature came through it, neither exploited before report). Formal verification announced as a strategic direction for NEAR ecosystem contracts.

## 9. Independent observations

- **Commented-out code in the fix**: #374 comments out rather than deletes the Notify paths and their tests. Unusual for a permanent security removal; plausibly chosen for speed and revertability. Risk: the dead code keeps compiling against live types and can be silently revived by a later refactor. Follow-up cleanup does not appear in the repo at time of writing.
- **Gas bumps as evidence**: the uniform raising of every resolve-callback gas constant in the removal PR suggests callbacks were operating close to gas limits before the incident, supporting (not proving) gas starvation of `ft_resolve_deposit` as a contributing factor in the failed rollback.
- **Silent error swallowing pre-existed**: #367's own notes state notification errors were "silently ignored" before 2 Oct. A system that swallows callback failures cannot maintain the credit/rollback invariant; this is the more structural reading of the root cause.
- **Known-dangerous pattern**: NEAR's own security documentation describes the exact failure mode (unexpected refunds, failed receiver calls, resolver accounting). The feature had two prior critical reports (Jan via bounty; Oct 7 via bounty) plus the exploited one. Feature removal was the correct call; the interesting question is why the January report produced a patch rather than removal.
- **Detection asymmetry**: the monitored pair (origin-chain vs NEAR-side supply) is a bridge-integrity invariant; the unmonitored pair (internal ledger vs contract balance) is the product's own solvency invariant. Protocol teams should monitor the invariants their own ledger introduces, not only the integration seams.

## 10. Lessons for NEAR builders

- Never credit an internal ledger synchronously in `ft_on_transfer` if the definitive token movement resolves later in an async callback; the rollback path must be proven equivalent to the refund the FT contract will execute. Follow the [safe-pattern checklist](https://docs.near.org/smart-contracts/security/cross-contract-calls/ft-transfer-call.md): bound refunds by original amount and receiver balance, keep resolvers private, test failed receivers, malicious return values, and out-of-gas cases.
- Treat every cross-contract "notification" to arbitrary receiver contracts as an attacker-controlled input: it can fail, stall, or return hostile values at any point in the promise chain ([private callbacks](https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md), [no panics in callbacks](https://docs.near.org/smart-contracts/security/cross-contract-calls/callback-panics.md)).
- Monitor solvency invariants (internal liabilities vs on-chain assets) with automatic pause on violation; that alone would have capped this incident at one faulty deposit.
- Budget callback gas so resolve paths cannot be starved by adversarial receivers consuming attached gas.

## 11. Sources

Primary: [official postmortem (X, Alex Shevchenko, 16 Oct 2026)](https://x.com/AlexAuroraDev/status/2111124226962870770). Repository evidence: [near/intents](https://github.com/near/intents), specifically PRs and commits cited in section 7. Protocol documentation: [NEAR docs index](https://docs.near.org/llms.txt) pages cited inline.

## 12. Related KB entries

- [NEAR Intents audit, Guvenkaya, February-March 2025](../audits/near-intents-guvenkaya-2025-02.md) - the pre-incident audit of the same contract suite: GUV-1 covers intent replay via failed intents (the same fail-then-repeat receipt semantics family this exploit lived in); baseline `6da9e2b3ab598f277d45fb356aee01a5d80ac0a6` predates the deposit-notification feature's exploited state.
- Patterns: [unchecked-promise-results](../patterns/unchecked-promise-results.md), [async-reentrancy](../patterns/async-reentrancy.md), [callback-panic-safety](../patterns/callback-panic-safety.md).
