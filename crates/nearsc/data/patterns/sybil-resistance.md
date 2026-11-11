---
title: "Sybil resistance: per-account rules in a cheap-account environment"
kind: pattern
severity: medium
tags: [identity, governance, accounts]
source: "https://docs.near.org/smart-contracts/security/sybil.md"
retrieved: 2026-11-10
confidence: verified-public
summary: "NEAR accounts are cheap and unverified, so one-account-one-vote and per-account airdrops are trivially multiplied; use token weighting, economic stake, reputation, or off-chain identity, and state the remaining trust assumption."
---

# Sybil resistance

## What it is

A sybil attack is one person or group operating many accounts to get more than
one share of a per-account system. NEAR makes account creation cheap and
requires no identity verification, so counting accounts is counting wallets,
not people.

## Why it matters

One-account-one-vote governance, per-account airdrops, per-account quotas, and
reputation systems are all exposed. An attacker can create many accounts, vote
or claim from each, and outweigh legitimate users. The result is not a
smart-contract bug in the narrow sense; it is a governance or distribution
failure caused by an invalid identity assumption. No on-chain identity
primitive on NEAR makes "one person" enforceable by the contract alone.

## Vulnerable pattern

```rust
pub fn vote(&mut self, support: bool) {
    let voter = env::signer_account_id();
    if self.votes.contains_key(&voter) {
        return;
    }
    self.votes.insert(&voter, &support);
    if support {
        self.yes += 1;
    } else {
        self.no += 1;
    }
}
```

The check prevents double voting from one account, not from one person. Creating
a second account costs less than the influence it buys in most governance
designs.

## Fixed pattern

The pragmatic mitigation is to make each additional unit of influence cost
something. Token-weighted voting with a minimum stake is the common shape.

```rust
pub fn vote(&mut self, support: bool) {
    let voter = env::signer_account_id();
    let weight = self.token.balance_of(voter.clone()).0;
    assert!(weight >= self.min_voting_stake, "below minimum voting stake");
    if self.votes.contains_key(&voter) {
        return;
    }
    self.votes.insert(&voter, &support);
    if support {
        self.yes += weight;
    } else {
        self.no += weight;
    }
}
```

Token weighting changes the attack from "create accounts" to "acquire stake".
That is the honest tradeoff: wealthy actors still have more influence. It
raises the cost and aligns voting power with economic exposure; it does not
prove uniqueness.

Reputation, time-locked participation, activity thresholds, and
proof-of-humanity services are complementary. Each adds cost or delay, and each
can be gamed or can exclude legitimate new users. For high-value governance,
combine token weight with an off-chain identity check or a multi-sig approval,
and document the trust assumption in the contract's own docs.

## How nearsc detects it

Not rule-linked in v0.1. Sybil resistance is an economic and identity design
property. There is no source-level pattern that distinguishes a legitimate
per-account rule from a vulnerable one without knowing the protocol's threat
model, so the scanner stays out of it and the KB entry exists so
`nearsc_patterns` can answer the question and point to the mitigation.

## False positives

Per-account rules are fine when the value at stake is low, when accounts are
sybil-resistant by construction (for example, one account per verified
organization), or when the design intentionally measures accounts rather than
people. A per-account airdrop to a fixed allowlist is a different shape from an
open one-account-one-vote poll.

## References

- [Sybil attacks (NEAR docs)](https://docs.near.org/smart-contracts/security/sybil.md)
- [DAOs (NEAR docs)](https://docs.near.org/primitives/dao)
