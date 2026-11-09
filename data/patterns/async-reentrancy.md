---
title: "Async reentrancy: state between a cross-contract call and its callback"
kind: pattern
severity: high
tags: [async, reentrancy, state]
source: "https://docs.near.org/smart-contracts/security/cross-contract-calls/reentrancy.md"
retrieved: 2026-11-10
confidence: verified-public
summary: "NEAR has no atomicity across receipts: any public method can run between a cross-contract call and its callback, so state committed before the callback can be exploited; delay critical state changes until the callback confirms success."
---

# Async reentrancy

## What it is

Cross-contract calls on NEAR are asynchronous. The initiating method returns,
the external receipt executes later, and the result arrives in a separate
callback receipt. Between those two points, any public method of the contract
can be called by anyone. State written before the external call is visible and
usable while the call is still pending.

## Why it matters

The EVM-style reentrancy guard does not map directly. The danger is not a
recursive call inside one transaction; it is a second transaction that
observes intermediate state. An attacker can withdraw a balance that was
credited before a staking or swap call resolved. If the external call later
fails, the callback may try to undo a balance that is already gone.

The canonical shape is `deposit_and_stake`: credit the user, call the
validator, reconcile in the callback. The attacker withdraws in the window
between the credit and the callback, and the failure path cannot recover the
funds.

## Vulnerable pattern

```rust
pub fn deposit_and_stake(&mut self) {
    let amount = env::attached_deposit();
    let account = env::predecessor_account_id();
    // Credits the spendable balance before the stake call resolves.
    let balance = self.balances.get(&account).unwrap_or(0);
    self.balances.insert(&account, &(balance + amount.as_yoctonear()));

    Promise::new(self.validator.clone())
        .function_call("deposit_and_stake".into(), vec![], amount, Gas::from_tgas(10))
        .then(Self::ext(env::current_account_id()).on_stake_complete(account));
}

pub fn withdraw(&mut self, amount: u128) {
    // Can run between the call above and its callback.
    let account = env::predecessor_account_id();
    let balance = self.balances.get(&account).unwrap_or(0);
    assert!(balance >= amount, "insufficient balance");
    self.balances.insert(&account, &(balance - amount));
    Promise::new(account).transfer(NearToken::from_yoctonear(amount));
}
```

## Fixed pattern

Hold the deposit as pending state and commit it only when the callback confirms
success. Check the promise result before changing the spendable balance.

```rust
pub fn deposit_and_stake(&mut self) {
    let amount = env::attached_deposit();
    let account = env::predecessor_account_id();
    self.pending.insert(&account, &amount.as_yoctonear());

    Promise::new(self.validator.clone())
        .function_call("deposit_and_stake".into(), vec![], amount, Gas::from_tgas(10))
        .then(Self::ext(env::current_account_id()).on_stake_complete(account));
}

#[private]
pub fn on_stake_complete(&mut self, account: AccountId) {
    let pending = self.pending.remove(&account).unwrap_or(0);
    match env::promise_result(0) {
        PromiseResult::Successful(_) => {
            let balance = self.balances.get(&account).unwrap_or(0);
            self.balances.insert(&account, &(balance + pending));
        }
        PromiseResult::Failed => {
            // No spendable balance was created; return the deposit.
            Promise::new(account).transfer(NearToken::from_yoctonear(pending));
        }
    }
}
```

The static guard rails are the ones nearsc can see: `#[private]` on the
callback (NS002) and explicit `PromiseResult::Failed` handling (NS004). The
ordering property itself is a design property, not a local syntax pattern.

## How nearsc detects it

Not rule-linked in v0.1. Detecting async reentrancy requires following state
writes and promise flows across methods, which is the v0.2 promise-flow
analysis scope (see [ROADMAP.md](../../docs/ROADMAP.md)). The shipped rules cover
the adjacent guard rails:

- [NS002](callback-privacy.md) flags a callback without `#[private]` or an
  equivalent predecessor check.
- [NS004](unchecked-promise-results.md) flags callbacks that ignore promise
  failure.

## False positives

There is no matcher, so there is no finding to triage. In manual review, a
balance credited before an external call is not automatically exploitable if
the credit is not spendable until the callback, or if the pending operation is
tracked separately. The finding is the ordering; the exploit is the ability to
act on the intermediate state.

## References

- [Reentrancy (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/reentrancy.md)
- [Callbacks (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md)
- [Cross-contract calls (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/crosscontract.md)
