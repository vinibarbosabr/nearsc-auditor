---
title: "Insecure randomness from block data"
kind: pattern
rule: NS009
severity: medium
tags: [randomness, gaming, validators, mev]
source: "https://docs.near.org/smart-contracts/security/random.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Treating block_index, block_timestamp, or predecessor-derived values as entropy lets validators and observers predict or bias outcomes; use env::random_seed with the documented caveats or an external oracle."
---

# Insecure randomness from block data

## What it is

Deterministic block fields (`block_index`, `block_timestamp`, `block_height`,
account ids, hashes of them) are visible before and during execution. Hashing
them does not add entropy. NEAR's `env::random_seed()` is validator-signed and
verifiable, but the validator producing the block can predict it, and can
choose whether to include a resolving transaction.

## Why it matters

Lotteries, NFT mints, and reward distributions built on block fields are
gameable: the validator (or any observer in the same block) computes the
outcome and inserts a winning transaction. Multi-block schemes reduce but do not
remove selective-mining advantage; commit-reveal or an external VRF is the
robust answer.

## Vulnerable pattern

```rust
pub fn draw_winner(&mut self) -> AccountId {
    let seed = env::block_timestamp() ^ env::block_index();
    let index = (seed % self.players.len() as u64) as usize;
    self.players.get(index).expect("player")
}
```

## Fixed pattern

```rust
pub fn draw_winner(&mut self) -> AccountId {
    // Validator-signed seed; acceptable only for low-stakes draws.
    let seed = env::random_seed();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&seed[..8]);
    let index = (u64::from_le_bytes(bytes) % self.players.len() as u64) as usize;
    self.players.get(index).expect("player")
}
```

For high-stakes draws, commit-reveal or an external VRF.

## How nearsc detects it (NS009)

The NS009 matcher flags expressions that derive an index, winner, or numeric
outcome from `block_index`, `block_timestamp`, `block_height`,
`predecessor_account_id`, or their hashes. Confidence `heuristic`.

## False positives

Timestamps used for deadlines or cooldowns (not entropy); `random_seed` with
documented low-stakes use.

## References

- [Random numbers (NEAR docs)](https://docs.near.org/smart-contracts/security/random.md)
- [Front-running (NEAR docs)](https://docs.near.org/smart-contracts/security/frontrunning.md)
- [Environment (NEAR docs)](https://docs.near.org/smart-contracts/anatomy/environment.md)
