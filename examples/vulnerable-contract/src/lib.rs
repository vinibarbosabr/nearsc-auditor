//! Deliberately vulnerable NEAR example contract.
//!
//! Seeds the bug classes nearsc detects, one obvious instance per class.
//! Parse-only fixture: not a workspace member and not meant to be deployed.

use near_sdk::collections::LookupMap;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise};

#[near(contract_state)]
pub struct VulnerableVault {
    owner: AccountId,
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl VulnerableVault {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner,
            balances: LookupMap::new(b"b"),
        }
    }

    #[payable]
    pub fn deposit(&mut self) {
        let account = env::predecessor_account_id();
        let amount = env::attached_deposit().as_yoctonear();
        let current = self.balances.get(&account).unwrap_or(0);
        self.balances.insert(&account, &(current + amount));
    }

    /// NS001 seed: transfer endpoint with no 1-yocto check.
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: u128) {
        let sender = env::predecessor_account_id();
        let balance = self.balances.get(&sender).unwrap_or(0);
        assert!(balance >= amount, "insufficient balance");
        self.balances.insert(&sender, &(balance - amount));
        Promise::new(receiver_id).transfer(NearToken::from_yoctonear(amount));
    }

    /// NS012 seed: privileged setter with no predecessor check.
    pub fn set_owner(&mut self, owner: AccountId) {
        self.owner = owner;
    }

    /// NS002 seed: callback used from `notify_receiver` below, missing #[private].
    pub fn on_deposit_complete(&mut self, amount: u128) {
        env::log_str(&format!("deposit complete: {amount}"));
    }

    pub fn notify_receiver(&self, receiver_id: AccountId, amount: u128) {
        Promise::new(receiver_id)
            .function_call(
                "on_deposit".to_string(),
                format!("{{\"amount\":{amount}}}").into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(5),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(25))
                    .on_deposit_complete(amount),
            );
    }

    /// NS005 seed: migration with init(ignore_state) and no predecessor guard.
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        Self {
            owner: env::predecessor_account_id(),
            balances: LookupMap::new(b"b"),
        }
    }
}
