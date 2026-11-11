---
title: "Unguarded init(ignore_state) migration"
kind: pattern
rule: NS005
severity: critical
tags: [upgrade, access-control, state]
source: "https://docs.near.org/smart-contracts/release/upgrade.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "A migration method annotated #[init(ignore_state)] replaces contract state; without a predecessor or owner guard, anyone can call it and wipe or reset the contract."
---

# Unguarded init(ignore_state) migration

## What it is

NEAR contracts upgrade by deploying new code, then running a migration method
that reads the old state and writes the new layout. `#[init(ignore_state)]`
tells near-sdk to skip the "already initialized" check, which means the method
can run again at any time. Such a method must be restricted to the contract
itself (ideally via `#[private]` and an owner check) or to the upgrade
authority.

## Why it matters

An open migration entry point is a state-reset primitive. An attacker calls it
to re-initialize ownership, clear balances, or deserialize attacker-chosen
state. This is one of the highest-impact bug classes on NEAR because it
bypasses every other access control in the contract.

## Vulnerable pattern

```rust
#[init(ignore_state)]
pub fn migrate() -> Self {
    // Anyone can call this and reset the contract.
    Self { owner: env::predecessor_account_id(), balances: LookupMap::new(b"b") }
}
```

## Fixed pattern

```rust
#[private]
#[init(ignore_state)]
pub fn migrate() -> Self {
    assert_eq!(env::predecessor_account_id(), env::current_account_id());
    let old: OldState = env::state_read().expect("old state");
    Self::from(old)
}
```

## How nearsc detects it (NS005)

The NS005 matcher flags `#[init(ignore_state)]` functions and migration-named
methods without `#[private]`, an owner/predecessor assertion, or an upgrade
authority check. Confidence `heuristic`: some designs gate the method through a
separate access-control macro.

## False positives

Migrations deliberately invoked by a DAO through a multi-sig flow with the
guard implemented in a wrapper; test-only helpers.

## Precedent

- [burrowland-blocksec-2022-03](../audits/burrowland-blocksec-2022-03.md): BUR-7, init
  configuration not validated in `init` (Medium, fixed).

## References

- [Updating contracts (NEAR docs)](https://docs.near.org/smart-contracts/release/upgrade.md)
- [State (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/storage.md)
- [NEAR security checklist (NEAR docs)](https://docs.near.org/smart-contracts/security/checklist.md)
