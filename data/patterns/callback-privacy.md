---
title: "Callback privacy: #[private] on cross-contract callbacks"
kind: pattern
rule: NS002
severity: high
tags: [async, callbacks, access-control]
source: "https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Cross-contract calls resolve in a callback method that must be public, but any account can invoke it unless it is marked #[private] or asserts predecessor == current_account_id."
---

# Callback privacy

## What it is

A cross-contract call is asynchronous: the initiating method returns, the
receipt executes later, and the result arrives in a separate callback method.
The callback must be part of the public ABI to receive the result, but it must
only be callable by the contract itself.

## Why it matters

If an attacker can call the callback directly, they can fabricate the "external
call succeeded" branch: mint balances, release escrow, or skip a refund. The
state machine assumes the callback follows a call the contract made; an open
callback breaks that assumption.

## Vulnerable pattern

```rust
pub fn on_transfer_complete(&mut self, amount: u128) {
    // Anyone can call this and fake a completed transfer.
    self.balances.insert(env::predecessor_account_id(), amount);
}

pub fn transfer(&mut self, to: AccountId) {
    Promise::new(to)
        .function_call("deposit".into(), vec![], NearToken::ZERO, Gas::from_tgas(10))
        .then(Self::ext(env::current_account_id()).on_transfer_complete(100));
}
```

## Fixed pattern

```rust
#[private]
pub fn on_transfer_complete(&mut self, amount: u128) {
    self.balances.insert(env::predecessor_account_id(), amount);
}
```

`#[private]` expands to an assertion that `predecessor_account_id()` equals
`current_account_id()`; an explicit `assert_eq!` is equivalent.

## How nearsc detects it (NS002)

The NS002 matcher collects functions used as the argument to `.then(...)`
(including the near-sdk `Self::ext(...).method(...)` idiom) and functions
annotated `#[callback]`, `#[callback_result]`, `#[callback_unwrap]`, or
`#[callback_vec]`, then flags the ones without `#[private]`, a manual
predecessor/current-account check, or an `assert_self`-style macro.
Confidence `spec`.

## False positives

Deliberately public "callback-like" methods that are not promise callbacks
(e.g. user-triggered settlement functions). The matcher sees shape, not intent.

## References

- [Private callbacks (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md)
- [Cross-contract calls (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/crosscontract.md)
- [NEAR security checklist (NEAR docs)](https://docs.near.org/smart-contracts/security/checklist.md)
