---
title: "Arbitrary promise target from user input"
kind: pattern
rule: NS010
severity: high
tags: [cross-contract, target-validation, allowlist]
source: "https://docs.near.org/smart-contracts/anatomy/actions.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Promise::new(target) with a caller-supplied target lets the caller steer the contract's cross-contract calls and attached value; targets must come from an allowlist or from state the caller cannot set."
---

# Arbitrary promise target from user input

## What it is

`Promise::new(account_id)` schedules actions on any NEAR account. When
`account_id` is a method parameter, the caller chooses where the contract
sends value and which contract receives its calls. Combined with attached
deposits or privileged callbacks, this turns the contract into a confused
deputy.

## Why it matters

Even when the amount is caller-funded, the contract's identity and any
privileges it holds (owner calls, callback assumptions, refunds) are applied to
an attacker-chosen account. Allowlists or state-derived targets keep the trust
boundary intact.

## Vulnerable pattern

```rust
pub fn payout(&mut self, target: AccountId, amount: NearToken) {
    // Caller chooses the target and the contract sends funds from its balance.
    Promise::new(target).transfer(amount);
}
```

## Fixed pattern

```rust
pub fn payout(&mut self, beneficiary: AccountId, amount: NearToken) {
    let allowed = self.allowlist.contains(&beneficiary);
    require!(allowed, "beneficiary not allowed");
    Promise::new(beneficiary).transfer(amount);
}
```

## How nearsc detects it (NS010)

The NS010 matcher flags `Promise::new(...)` and deploy/function-call builders
whose target is a method parameter (or a field derived from one in the same
method) without a preceding allowlist or ownership check. Confidence
`heuristic`.

## False positives

Escrows and routers whose entire purpose is to pay caller-specified accounts
with caller-supplied funds; targets validated by an upstream method.

## References

- [Transfers and actions (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/actions.md)
- [Cross-contract calls (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/crosscontract.md)
- [Private callbacks (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md)
