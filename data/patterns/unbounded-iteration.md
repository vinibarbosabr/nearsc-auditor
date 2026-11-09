---
title: "Unbounded iteration over collections in public methods"
kind: pattern
rule: NS007
severity: medium
tags: [gas, dos, pagination, collections]
source: "https://docs.near.org/smart-contracts/anatomy/best-practices.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Public methods that loop over an unbounded collection consume more gas as state grows; once the loop exceeds the gas limit the method (and any flow that depends on it) can be bricked."
---

# Unbounded iteration over collections

## What it is

A loop in a public method whose iteration count is controlled by state growth:
iterating a `Vector`, `UnorderedMap`, or `UnorderedSet` without pagination, or
scanning all accounts to distribute rewards. NEAR's gas limit per receipt is
fixed, so the loop has a hard ceiling; the contract controls when it is hit.

## Why it matters

An attacker can grow the collection cheaply (see the storage-griefing pattern)
and then the method runs out of gas permanently. If that method is on a critical
path (epoch update, reward distribution, migration), the contract is bricked
until state is manually cleaned. BlockSec flagged exactly this class in LiNEAR:
`epoch_update_rewards` may not work with unlimited beneficiaries.

## Vulnerable pattern

```rust
pub fn epoch_update_rewards(&mut self) {
    for account_id in self.accounts.iter() {
        let reward = self.compute_reward(&account_id);
        self.rewards.insert(&account_id, &reward);
    }
}
```

## Fixed pattern

```rust
pub fn update_rewards_batch(&mut self, start: u64, limit: u64) {
    let end = (start + limit).min(self.accounts.len());
    for index in start..end {
        let account_id = self.accounts.get(index).expect("in range");
        let reward = self.compute_reward(&account_id);
        self.rewards.insert(&account_id, &reward);
    }
}
```

## How nearsc detects it (NS007)

The NS007 matcher flags `for`/`while` loops and iterator chains inside public
methods that iterate a collection field without an explicit bound or cursor
parameter. Confidence `heuristic`: bounded loops over constants are not
findings.

## False positives

Loops over compile-time constants; loops whose collection is provably capped at
a small number and the cap is enforced on insert.

## References

- [Best practices (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/best-practices.md)
- [Collections (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/collections.md)
- [Storage cost attacks (NEAR docs)](https://docs.near.org/smart-contracts/security/storage.md)
