---
title: "Panic-free callbacks: no unwrap, expect, or indexing in resolve paths"
kind: pattern
rule: NS003
severity: medium
tags: [async, callbacks, reliability, refunds]
source: "https://docs.near.org/smart-contracts/security/cross-contract-calls/callback-panics.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "A callback that panics aborts its cleanup and refund path; the promise result is already consumed, so the contract is left in the pre-callback state with user funds possibly inside it."
---

# Panic-free callbacks

## What it is

A promise callback runs once. If it panics, the runtime rolls back the
callback's own state changes, but the external call already happened and the
promise result is gone. There is no retry: whatever cleanup the callback owed
(rollback, refund, pending-state release) never runs.

## Why it matters

Callbacks are the failure-handling layer of every asynchronous flow. Panics
inside them convert a recoverable external failure into stuck funds or an
inconsistent ledger. NEAR's own security guide treats panics in callbacks as a
separate vulnerability class.

## Vulnerable pattern

```rust
#[private]
pub fn on_stake_complete(&mut self, #[callback_result] result: Result<(), PromiseError>) {
    let pending = self.pending.get(&env::predecessor_account_id()).unwrap(); // panics if missing
    if result.is_err() {
        self.refund(pending.amount);
    }
    self.pending.remove(&env::predecessor_account_id());
}
```

## Fixed pattern

```rust
#[private]
pub fn on_stake_complete(&mut self, #[callback_result] result: Result<(), PromiseError>) {
    let Some(pending) = self.pending.get(&env::predecessor_account_id()) else {
        env::log_str("callback: no pending entry");
        return;
    };
    if result.is_err() {
        self.refund(pending.amount);
    }
    self.pending.remove(&env::predecessor_account_id());
}
```

## How nearsc detects it (NS003)

The NS003 matcher inspects `#[private]` callback bodies (and functions used in
`.then(...)`) for `unwrap`, `expect`, `panic!`, `assert!` on external data, and
slice indexing. Confidence `heuristic`: some panic paths are unreachable by
construction, so a human confirms.

## False positives

Indexing a fixed-size array with a constant; `expect` on values the contract
itself just constructed; callbacks whose only job is to log.

## References

- [Do not panic in callbacks (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/callback-panics.md)
- [Callbacks can fail (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/callback-failures.md)
- [Refund NEAR tokens (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/refunds.md)
