---
title: "One-yocto authorization on asset transfers"
kind: pattern
rule: NS001
severity: high
tags: [access-control, one-yocto, nep-141, nep-171, wallets]
source: "https://docs.near.org/smart-contracts/security/one_yocto.md"
retrieved: 2026-11-09
confidence: verified-public
summary: "Asset-moving methods that do not require a 1-yoctoNEAR deposit can be called through a function-call access key stored in a website, so the user never explicitly approves the transfer."
---

# One-yocto authorization on asset transfers

## What it is

NEAR wallets issue two kinds of access keys. A full-access key lives in the
wallet and can attach NEAR to a call. A function-call key lives in the website
the user signed in to, can only call whitelisted methods, and **cannot attach a
deposit**. Requiring exactly 1 yoctoNEAR (`assert_one_yocto()`) on sensitive
methods therefore proves the call came through the wallet with a user
confirmation, not through a website-held key.

## Why it matters

`ft_transfer`, `ft_transfer_call`, `nft_transfer`, and `nft_transfer_call` move
valuable assets while acting on `predecessor_account_id()`. Without the
1-yocto check, a compromised or malicious frontend can empty a user's balance
through the function-call key it holds. NEP-141/NEP-171 reference
implementations require the check for this reason.

## Vulnerable pattern

```rust
pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
    // No assert_one_yocto(): a website-held function-call key can call this.
    self.internal_transfer(env::predecessor_account_id(), receiver_id, amount.0);
}
```

## Fixed pattern

```rust
pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
    assert_one_yocto();
    self.internal_transfer(env::predecessor_account_id(), receiver_id, amount.0);
}
```

## How nearsc detects it (NS001)

The NS001 matcher looks for methods named `ft_transfer`, `ft_transfer_call`,
`nft_transfer`, or `nft_transfer_call` that move value on behalf of the caller
without an `assert_one_yocto()` call, an `attached_deposit` check, or an
equivalent predecessor assertion. Confidence `spec`: the rule encodes the
wallet-authorization pattern the standards assume.

## False positives

Methods that are intentionally custodial or session-based and document why the
yocto check is not required; wrappers that delegate to an internal method that
performs the check.

## Precedent

- [potlock-guvenkaya-2024-01](../audits/potlock-guvenkaya-2024-01.md): GUV-13,
  privileged pot/sybil functions without `assert_one_yocto` were callable through
  function-call access keys (Low, fixed).

## References

- [Require one yoctoNEAR (NEAR docs)](https://docs.near.org/smart-contracts/security/one_yocto.md)
- [Access keys (NEAR docs)](https://docs.near.org/protocol/accounts-contracts/access-keys.md)
- [NEAR security checklist (NEAR docs)](https://docs.near.org/smart-contracts/security/checklist.md)
