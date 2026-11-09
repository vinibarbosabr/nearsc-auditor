---
title: "Sputnik DAO staking: repeated storage_withdraw (issue 239)"
kind: audit
project: sputnik-dao
year: 2026
source: "https://github.com/near-daos/sputnik-dao-contract/issues/239"
retrieved: 2026-11-09
confidence: verified-public
tags: [dao, storage-accounting, refunds, access-control]
summary: "Public issue: sputnik-staking's storage_withdraw transfers NEAR to the user but never reduces the recorded refundable storage balance, so the same storage credit can be withdrawn repeatedly."
---

# Sputnik DAO staking: repeated `storage_withdraw`

**Target:** `near-daos/sputnik-dao-contract`, `sputnik-staking` contract.
Public issue #239, filed 2026-07-04 with a unit test and a sandbox integration
repro.

## What the issue reports

`storage_withdraw` pays out the user's refundable storage balance:

```rust
#[payable]
fn storage_withdraw(&mut self, amount: Option<NearToken>) -> StorageBalance {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let user = self.internal_get_user(&account_id);
    let available = user.storage_available();
    let amount = amount.unwrap_or(available);
    assert!(amount <= available, "ERR_STORAGE_WITHDRAW_TOO_MUCH");
    Promise::new(account_id.clone()).transfer(amount).detach();
}
```

The withdrawal path does not reduce the user's recorded refundable storage
balance, so the same credit can be withdrawn repeatedly: the contract pays out
NEAR each time until its balance is gone.

## Why it matters for nearsc

- Pure storage-accounting class (NS008 family): the ledger that backs a refund
  claim must be debited in the same operation that pays it out.
- The fix direction is the general rule nearsc encodes: any method that
  transfers value out of the contract must first decrement the internal claim
  that authorized the transfer (checks-effects-interactions, extended to
  storage credits).
- Public issue, reproducible tests, no client-confidential material.

## Source

Public issue with reproducer:
<https://github.com/near-daos/sputnik-dao-contract/issues/239>.
