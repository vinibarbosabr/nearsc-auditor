---
title: "Storage griefing on user-controlled inserts"
kind: pattern
rule: NS008
severity: medium
tags: [storage, griefing, deposits, nep-145]
source: "https://docs.near.org/smart-contracts/security/storage.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Writing user-controlled data into contract storage without charging the user locks the contract's NEAR balance; repeated small inserts can drain the balance and freeze the contract."
---

# Storage griefing on user-controlled inserts

## What it is

On NEAR, contracts stake NEAR proportional to the state they store. If a method
inserts caller-controlled data into a collection without requiring the caller to
cover the storage cost, every insert spends the contract's own balance. NEP-145
storage management is the standard answer for FT/NFT contracts; ad-hoc contracts
need an equivalent.

## Why it matters

The attack is cheap and repeatable: many small inserts, each paid for by the
contract. Hacken's 2024 LiNEAR review (F-2024-1979) measured a new `Account`
struct at ~0.004 NEAR of contract-paid storage while the user paid ~0.0005 NEAR
in gas, and rated it Medium. Burrow's 2022 audits found storage-accounting
errors in liquidation paths. At scale the contract runs out of usable balance
and every storage-touching method fails.

## Vulnerable pattern

```rust
#[payable]
pub fn add_note(&mut self, text: String) {
    // Auth only; the attached deposit is ignored and storage is not charged.
    let author = env::predecessor_account_id();
    self.notes.insert(&author, &text);
}
```

## Fixed pattern

```rust
#[payable]
pub fn add_note(&mut self, text: String) {
    let author = env::predecessor_account_id();
    let before = env::storage_usage();
    self.notes.insert(&author, &text);
    let cost = env::storage_byte_cost().saturating_mul((env::storage_usage() - before).into());
    require!(
        env::attached_deposit() >= cost,
        "attach enough deposit to cover storage"
    );
}
```

## How nearsc detects it (NS008)

The NS008 matcher flags collection `insert`/`set` calls with user-controlled
keys or values inside public methods that neither measure
`storage_usage()`/`storage_byte_cost()` nor implement NEP-145 storage
accounting. Confidence `heuristic`.

## False positives

Collections with bounded size per account; protocols that intentionally
subsidize storage for a vetted allowlist.

## References

- [Storage cost attacks (NEAR docs)](https://docs.near.org/smart-contracts/security/storage.md)
- [Storage staking (NEAR docs)](https://docs.near.org/protocol/storage/storage-staking.md)
- [Storage management standard (NEP-145)](https://nomicon.io/Standards/StorageManagement)
