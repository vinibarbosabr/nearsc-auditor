---
title: "Unguarded privileged setters"
kind: pattern
rule: NS012
severity: medium
tags: [access-control, admin, setters]
source: "https://docs.near.org/smart-contracts/anatomy/environment.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Admin-style methods (set_*, update_*, pause_*, withdraw_*, admin_*) that do not assert the caller let anyone rewrite ownership, pause the contract, or move treasury funds."
---

# Unguarded privileged setters

## What it is

Methods that change trust-critical configuration: owner, managers, treasury,
whitelists, pause state, fee parameters, withdrawal addresses. They are only
safe if the caller is checked against `predecessor_account_id()` (not
`signer_account_id()`, which differs for meta transactions and relayers) or
against a role/DAO contract.

## Why it matters

Access-control omissions in setters are the cheapest critical bug to exploit:
one call transfers ownership or drains the treasury. The NEAR security checklist
lists correct predecessor/signer usage as a top item. Hacken's LiNEAR review
also flagged missing events on exactly this set of methods, which makes abuse
harder to detect.

## Vulnerable pattern

```rust
pub fn set_owner(&mut self, owner: AccountId) {
    // No caller check.
    self.owner = owner;
}

pub fn pause(&mut self) {
    self.paused = true;
}
```

## Fixed pattern

```rust
pub fn set_owner(&mut self, owner: AccountId) {
    self.assert_owner();
    self.owner = owner;
    Event::OwnerChanged { old: old_owner, new: owner }.emit();
}

pub fn pause(&mut self) {
    self.assert_owner();
    self.paused = true;
}
```

## How nearsc detects it (NS012)

The NS012 matcher flags public methods whose names start with `set_`, `update_`,
`pause_`, `unpause`, `withdraw_`, or `admin_` that do not assert the caller
against predecessor, owner, or a role/DAO account. Confidence `heuristic`.

## False positives

Methods whose names match the prefix but are intentionally permissionless
(e.g. `update_price` from an oracle callback); checks implemented in a
procedural macro.

## References

- [Environment: predecessor and signer (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/environment.md)
- [NEAR security checklist (NEAR docs)](https://docs.near.org/smart-contracts/security/checklist.md)
- [Access keys (NEAR docs)](https://docs.near.org/protocol/accounts-contracts/access-keys.md)
