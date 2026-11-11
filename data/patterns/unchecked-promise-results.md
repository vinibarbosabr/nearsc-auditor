---
title: "Unchecked promise results in callbacks"
kind: pattern
rule: NS004
severity: high
tags: [async, callbacks, promise-results, accounting]
source: "https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "A callback that commits state without inspecting PromiseResult can treat a failed cross-contract call as success, leaving the contract over-credited or under-collateralized."
---

# Unchecked promise results

## What it is

Every cross-contract call resolves with a `PromiseResult` (`Success` or
`Failed`). In near-sdk the common shapes are `#[callback_result] result:
Result<T, PromiseError>`, `env::promise_result(0)`, or
`env::promise_results_count()`. A callback that ignores the result and commits
state unconditionally is trusting an external call it does not control.

## Why it matters

The NEAR Intents deposit-notification exploit is the canonical case: the
contract credited an internal ledger, the notification leg failed, the FT
contract refunded the tokens, and the credit stayed (see the postmortem entry
in this knowledge base). Committing state on an unverified promise outcome is
how "external call failed" becomes "contract thinks it succeeded".

## Vulnerable pattern

```rust
#[private]
pub fn on_deposit(&mut self, account: AccountId, amount: u128) {
    // Never looks at the promise result.
    self.balances.insert(&account, &amount);
}
```

## Fixed pattern

```rust
#[private]
pub fn on_deposit(&mut self, account: AccountId, amount: u128) {
    match env::promise_result(0) {
        PromiseResult::Successful(_) => {
            self.balances.insert(&account, &amount);
        }
        _ => {
            self.pending.remove(&account);
            // refund or roll back here
        }
    }
}
```

## How nearsc detects it (NS004)

The NS004 matcher flags callbacks that mutate state but never read
`PromiseResult`, `promise_result`, `promise_results_count`, or a
`#[callback_result]` parameter. Confidence `heuristic`: callbacks that only log
or read state are not findings.

## False positives

Callbacks whose mutation is safe regardless of the outcome (e.g. clearing a
pending marker that must be cleared either way); calls whose failure the
contract cannot act on.

## Precedent

- [potlock-guvenkaya-2024-01](../audits/potlock-guvenkaya-2024-01.md): GUV-3, refund
  target computed from `predecessor_account_id()` inside a `#[private]` callback; failed
  sybil checks paid the contract instead of the donor (High, fixed).

## References

- [Private callbacks (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md)
- [Callbacks can fail (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/callback-failures.md)
- [Token transfer flow (NEAR docs)](https://docs.near.org/protocol/data-flow/token-transfer-flow.md)
