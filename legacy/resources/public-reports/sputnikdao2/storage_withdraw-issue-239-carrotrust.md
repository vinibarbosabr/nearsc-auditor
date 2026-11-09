---
name: Repeated `storage_withdraw` can withdraw the same storage credit multiple times
project: Sputnik DAO Contract
repository: https://github.com/near-daos/sputnik-dao-contract/
security researcher: Carrotrust
date: 2026-07-04
file link: https://github.com/near-daos/sputnik-dao-contract/issues/239
---
# Repeated `storage_withdraw` can withdraw the same storage credit multiple times #239

## Summary

The `sputnik-staking` contract allows a registered user to call `storage_withdraw` multiple times against the same storage credit because the withdrawal path transfers NEAR out but does not reduce the user’s recorded refundable storage balance.

This is reproducible both at unit-test level and with a sandbox integration test using deployed WASM.

## Affected code

### `sputnik-staking/src/storage_impl.rs`

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
    self.storage_balance_of(account_id).unwrap()
}
```

**Problem:**

- `storage_withdraw` transfers amount
- but it never updates `user.near_amount`
- so the user’s refundable storage credit remains unchanged after the first withdrawal

`sputnik-staking/src/user.rs`

```
pub fn storage_available(&self) -> NearToken {
    env::storage_byte_cost()
        .saturating_mul(self.near_amount.as_yoctonear() - self.storage_used as u128)
}
```

## Why this is a bug

A storage refund path should reduce the user’s refundable balance after refunding it.  
Current behavior:

1. A user registers with `storage_deposit`.
2. The user calls `storage_withdraw`.
3. The contract transfers NEAR to the user.
4. The user’s stored refundable balance is not reduced.
5. The user can call `storage_withdraw` again for the same amount.  
    That means the same storage credit can be withdrawn more than once.

## Suggested fix

After a successful `storage_withdraw`, reduce the user’s stored refundable storage balance before returning the new `StorageBalance`.  
At minimum:

- decrement `user.near_amount` by the withdrawn amount
- save the updated user record
- ensure `storage_balance_of(account).available` decreases after the first withdrawal  
    It would also be worth reviewing the `storage_available()` formula itself, since it currently multiplies by `storage_byte_cost()` again.