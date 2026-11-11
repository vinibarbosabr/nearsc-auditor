---
title: "Missing deposit refund on early failure"
kind: pattern
rule: NS011
severity: low
tags: [refunds, payable, funds-safety]
source: "https://docs.near.org/smart-contracts/security/cross-contract-calls/refunds.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "A payable method that accepts a deposit, then fails an assertion or bails out before moving the funds, keeps the user's NEAR inside the contract unless an explicit refund path exists."
---

# Missing deposit refund on early failure

## What it is

On NEAR, a deposit attached to a function call is transferred to the contract
before the method runs. If the method panics, the deposit is returned to the
predecessor automatically. But a method that does not panic and simply returns
early (or takes a failure branch) keeps the attached NEAR in the contract with
no accounting entry, unless it explicitly refunds.

## Why it matters

User funds get stuck in the contract without a claim path. This is a common
review finding in payable flows: deposit accepted, validation fails, nothing
refunded and nothing recorded. NEAR's refund guidance and the security checklist
cover this class.

## Vulnerable pattern

```rust
#[payable]
pub fn mint_ticket(&mut self) {
    if self.sold_out {
        // Returns without refunding the attached deposit.
        env::log_str("sold out");
        return;
    }
    self.mint();
}
```

## Fixed pattern

```rust
#[payable]
pub fn mint_ticket(&mut self) {
    if self.sold_out {
        let refund = env::attached_deposit();
        Promise::new(env::predecessor_account_id()).transfer(refund);
        return;
    }
    self.mint();
}
```

## How nearsc detects it (NS011)

The NS011 matcher flags `#[payable]` methods that take an early return or
failure branch after reading `attached_deposit()` where neither a refund
promise nor a storage/accounting write covers the deposit. Confidence
`heuristic`.

## False positives

Methods that always panic on failure (deposit auto-returns); flows that record
the deposit as a user balance before returning.

## Precedent

- [sputnikdao2-storage-withdraw-2026-07](../audits/sputnikdao2-storage-withdraw-2026-07.md):
  SPN-239, `storage_withdraw` transfers NEAR out without debiting the refundable balance -
  the sibling failure where the refund claim is never consumed (public issue).

## References

- [Refund NEAR tokens (NEAR docs)](https://docs.near.org/smart-contracts/security/cross-contract-calls/refunds.md)
- [NEAR security checklist (NEAR docs)](https://docs.near.org/smart-contracts/security/checklist.md)
- [Transfers and actions (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/actions.md)
