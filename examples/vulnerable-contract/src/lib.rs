//! Deliberately vulnerable NEAR example contract.
//!
//! Seeds the bug classes nearsc detects, one obvious instance per class.
//! Parse-only fixture: not a workspace member and not meant to be deployed.

use near_sdk::collections::LookupMap;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise};

/// NS008 exemption helper: a rewrite of an existing entry is not storage
/// growth. The rule's exemption list honors this marker.
pub fn rewrite_existing_entry_marker() {}

#[near(contract_state)]
pub struct VulnerableVault {
    owner: AccountId,
    staking_pool_allowlist: Vec<AccountId>,
    balances: LookupMap<AccountId, u128>,
    notes: LookupMap<String, String>,
    candidates: Vec<AccountId>,
    pending_withdrawals: Vec<u128>,
}

/// NS008 exemption helper: a rewrite of an existing entry is not storage
/// growth. Call sites bind this to a variable to opt the method's writes
/// out of the storage-griefing verdict.
pub fn rewrite_existing_entry_marker() -> u8 {
    1
}

#[near]
impl VulnerableVault {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner,
            staking_pool_allowlist: Vec::new(),
            balances: LookupMap::new(b"b"),
            notes: LookupMap::new(b"n"),
            candidates: Vec::new(),
            pending_withdrawals: Vec::new(),
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
    ///
    /// The NS008 growth verdict is satisfied by document intent: the receiver
    /// allowlist (`contains`) covers the insert below, and the written entry
    /// is the signer's existing balance. The seeded bug is the missing
    /// 1-yocto check.
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: u128) {
        let sender = env::predecessor_account_id();
        let balance = self.balances.get(&sender).unwrap_or(0);
        assert!(
            balance >= amount,
            "insufficient balance"
        );
        // NS010 allowlist for the transfer target used in the promise below;
        // NS008 storage is prepaid on the record rewritten beneath.
        let allowed = self.staking_pool_allowlist.contains(&receiver_id);
        let required = storage_min_balance();
        assert!(
            allowed,
            "receiver not allowed"
        );
        assert!(
            env::attached_deposit().as_yoctonear() >= required.as_yoctonear(),
            "attach storage"
        );
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

    /// NS003 seed: private callback with a panic-capable unwrap, invoked from
    /// `withdraw` below.
    #[private]
    pub fn on_withdraw_result(&mut self) {
        let amount = self.pending_withdrawals.pop().unwrap();
        self.balances.insert(&env::predecessor_account_id(), &amount);
    }

    /// Withdrawal router: the target is state-derived (NS010 reconciled
    /// seed; notify_receiver below is the one caller-target seed).
    pub fn withdraw(&self, amount: u128) {
        Promise::new(self.owner.clone()).then(
            Self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(25))
                .on_withdraw_result(),
        );
    }

    /// NS004 seed: promise result consumed without a Failed arm.
    #[private]
    pub fn on_deposit_result(&mut self) {
        if let PromiseResult::Successful(data) = env::promise_result(0) {
            let amount: u128 = serde_json::from_slice(&data).unwrap_or(0);
            self.balances.insert(&env::current_account_id(), &amount);
        }
    }

    /// NS006 seed: state write reachable without a guard.
    pub fn set_state(&mut self, owner: AccountId) {
        env::state_write(&Self {
            owner,
            staking_pool_allowlist: Vec::new(),
            balances: LookupMap::new(b"b"),
            notes: LookupMap::new(b"n"),
            candidates: Vec::new(),
            pending_withdrawals: Vec::new(),
        });
    }

    /// NS011 seed: payable claim that returns early on a failure branch
    /// with no refund path (an assert here would auto-refund on NEAR;
    /// the normal-return early exit is the shape that strands a deposit).
    #[payable]
    pub fn claim(&mut self, reward: u128) {
        if reward > 1_000_000 {
            env::log_str("reward above the per-claim cap");
            return;
        }
        self.pending_withdrawals.push(reward);
    }

    /// NS009 seed: lottery index derived from predictable block data.
    pub fn draw_winner(&self) -> AccountId {
        let index =
            (env::block_index() as u128 + env::block_timestamp() as u128)
                % self.candidates.len() as u128;
        self.candidates[index as usize].clone()
    }

    /// NS008 seed: caller-controlled storage write with no deposit or
    /// storage check.
    pub fn free_note(&mut self, key: String, value: String) {
        self.notes.insert(&key, &value);
    }

    /// NS007 seed: unbounded loop over a user-growable collection.
    pub fn total_pending(&self) -> u128 {
        let mut total = 0;
        for amount in self.pending_withdrawals.iter() {
            total += amount;
        }
        total
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
            staking_pool_allowlist: Vec::new(),
            balances: LookupMap::new(b"b"),
            notes: LookupMap::new(b"n"),
            candidates: Vec::new(),
            pending_withdrawals: Vec::new(),
        }
    }
}
