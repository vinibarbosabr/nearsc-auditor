---
title: "Front-running: validator ordering and first-come-first-served rewards"
kind: pattern
severity: medium
tags: [mev, validators, commit-reveal]
source: "https://docs.near.org/smart-contracts/security/frontrunning.md"
retrieved: 2026-11-10
confidence: verified-public
summary: "Validators see the transaction pool and choose ordering, so first-come-first-served rewards and public answers can be copied and landed first; commit-reveal, delays, or randomized selection remove the advantage."
---

# Front-running

## What it is

A validator can inspect pending transactions, decide their order, and insert
its own transaction. On NEAR the transaction pool is visible to validators
before execution. Any contract rule that pays the first correct submission, the
first mint, or the best price can be front-run by the party that controls
inclusion.

## Why it matters

Reward games, limited mints, auctions, and oracle updates are the common
targets. The attack does not need to break the contract: the attacker copies a
public answer or trade intent and lands an identical transaction first. The
legitimate user's transaction then fails or receives nothing.

Sandwich shapes are the trading variant: the attacker places a transaction
before and after a large trade and profits from the price impact. Priority gas
auctions are the competitive variant: multiple actors bid for the front-run
position, which raises costs without improving the user's outcome.

## Vulnerable pattern

```rust
pub fn solve_puzzle(&mut self, puzzle_id: String, solution: String) {
    let expected = self.answers.get(&puzzle_id).unwrap_or_default();
    if solution == expected && !self.solved.contains_key(&puzzle_id) {
        // The first transaction with the answer wins; a validator can copy it.
        self.solved.insert(&puzzle_id, &env::signer_account_id());
        self.rewards
            .insert(&env::signer_account_id(), &NearToken::from_near(1));
    }
}
```

## Fixed pattern

Commit-reveal removes the answer from the transaction pool during the phase
where ordering matters.

```rust
pub fn commit_solution(&mut self, puzzle_id: String, commitment: Vec<u8>) {
    // commitment = sha256(solution || secret)
    self.commits
        .insert(&(env::signer_account_id(), puzzle_id), &commitment);
}

pub fn reveal_solution(&mut self, puzzle_id: String, solution: String, secret: Vec<u8>) {
    let key = (env::signer_account_id(), puzzle_id);
    let commitment = self.commits.get(&key).expect("commitment");
    let revealed = env::sha256([solution.as_bytes(), secret.as_slice()].concat());
    assert_eq!(revealed, commitment, "commitment mismatch");
    // Winner selection happens after the reveal window, not on first reveal.
    self.reveals.insert(&env::signer_account_id(), &solution);
}
```

The contract does not treat an answer as proof during the commit phase. After
the reveal window closes, it verifies every hash and selects a winner by a rule
the validator cannot influence: split among all correct solvers, random
selection over verified reveals, or a delayed draw. Time-delayed execution and
private transaction pools are weaker variants and depend on infrastructure.
For the selection step, do not use block data as entropy: that is the adjacent
NS009 class, see [insecure-randomness.md](insecure-randomness.md).

## How nearsc detects it

Not rule-linked in v0.1. Front-running is an ordering and market property, not
a local source pattern; a static scanner cannot see the validator's transaction
pool or the contract's economic incentives. The adjacent detection is NS009:
when winner selection uses `block_timestamp`, `block_index`, or
predecessor-derived values, the NS009 matcher flags the predictable entropy.
Commit-reveal conformance is a protocol-level review, not a v0.1 matcher.

## False positives

First-come-first-served flows with no valuable reward are not interesting to a
front-runner. Queued or batching designs that execute later may be safe even
when the code reads like first-come. The risk grows with the reward value and
with how much information the pending transaction exposes.

## References

- [Front-running (NEAR docs)](https://docs.near.org/smart-contracts/security/frontrunning.md)
- [Insecure randomness from block data](insecure-randomness.md)
- [Ethereum is a dark forest (Paradigm)](https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest)
