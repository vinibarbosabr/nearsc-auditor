---
title: "Unguarded upgrade and state-write paths"
kind: pattern
rule: NS006
severity: critical
tags: [upgrade, access-control, state]
source: "https://docs.near.org/smart-contracts/release/upgrade.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Methods that write whole-contract state (state_write, migrate deserialization, code deploy helpers) must be callable only by the contract itself or the upgrade authority."
---

# Unguarded upgrade and state-write paths

## What it is

The upgrade surface is everything that can replace code or whole state:
`env::state_write`, `State::new` after `state_remove`, migration
deserialization helpers, and any method that calls the deploy action. On NEAR
the deployed code can only be replaced by the account itself, so these paths
must be unreachable from arbitrary predecessors.

## Why it matters

A reachable state-write path is equivalent to arbitrary storage control:
attacker-chosen owner, balances, or code hash. It is the same trust boundary as
an admin key. Bugs here are critical by definition.

## Vulnerable pattern

```rust
pub fn reset_state(state: Vec<u8>) {
    env::state_write(&state);
}

pub fn migrate_from(state: Vec<u8>) {
    let new_state: NewState = near_sdk::borsh::from_slice(&state).unwrap();
    new_state.save();
}
```

## Fixed pattern

```rust
#[private]
pub fn reset_state(state: Vec<u8>) {
    assert_eq!(env::predecessor_account_id(), env::current_account_id());
    env::state_write(&state);
}
```

## How nearsc detects it (NS006)

The NS006 matcher flags calls to `state_write`, `state_remove`, and
migration-style deserialization inside public methods that do not assert the
caller (predecessor, owner, or DAO account). Confidence `heuristic`.

## False positives

Admin methods guarded by a custom `assert_owner!` macro or by a role contract
call; methods on non-contract helper types that never touch runtime state.

## References

- [Updating contracts (NEAR docs)](https://docs.near.org/smart-contracts/release/upgrade.md)
- [State (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/storage.md)
- [Global contracts (NEAR docs)](https://docs.near.org/smart-contracts/global-contracts.md)
