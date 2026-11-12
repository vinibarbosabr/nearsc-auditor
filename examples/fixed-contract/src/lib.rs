//! Deliberately fixed NEAR example contract.
//!
//! The patched twin of `examples/vulnerable-contract`: same surface, every
//! seeded bug fixed with the guard the matching rule recognizes. Parse-only
//! fixture: not a workspace member and not meant to be deployed. `nearsc
//! scan` on this directory emits zero findings; the vulnerable twin emits
//! twelve.

use near_sdk::collections::LookupMap;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise, PromiseResult};

/// NS008 exemption note: a rewrite of an existing entry is not storage
/// growth. The deposit/transfer endpoints below either charge storage or
/// carry `#[payable]`.
#[near(contract_state)]
pub struct FixedVault {
    owner: AccountId,
    staking_pool_allowlist: Vec<AccountId>,
    balances: LookupMap<AccountId, u128>,
    notes: LookupMap<String, String>,
    candidates: Vec<AccountId>,
    pending_withdrawals: Vec<u128>,
}

#[near]
impl FixedVault {
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

    /// NS001 fix: the transfer enforces the 1-yoctoNEAR attached deposit
    /// (NEP-141/171). The `attached_deposit` mention also satisfies NS008's
    /// storage markers, and the allowlist check keeps NS010 quiet.
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: u128) {
        assert_eq!(
            env::attached_deposit(),
            NearToken::from_yoctonear(1),
            "attach exactly 1 yoctoNEAR (NEP-141)"
        );
        let sender = env::predecessor_account_id();
        let balance = self.balances.get(&sender).unwrap_or(0);
        assert!(balance >= amount, "insufficient balance");
        let allowed = self.staking_pool_allowlist.contains(&receiver_id);
        assert!(allowed, "receiver not allowed");
        self.balances.insert(&sender, &(balance - amount));
        Promise::new(receiver_id).transfer(NearToken::from_yoctonear(amount));
    }

    /// NS012 fix: the setter checks the caller against the on-chain owner.
    pub fn set_owner(&mut self, owner: AccountId) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "ERR_ONLY_OWNER"
        );
        self.owner = owner;
    }

    /// NS002 fix: the callback is private to the contract.
    #[private]
    pub fn on_deposit_complete(&mut self, amount: u128) {
        env::log_str(&format!("deposit complete: {amount}"));
    }

    /// NS003 fix: the private callback stays panic-free (no unwrap, no
    /// expect, no indexing).
    #[private]
    pub fn on_withdraw_result(&mut self) {
        if let Some(amount) = self.pending_withdrawals.pop() {
            self.balances.insert(&env::predecessor_account_id(), &amount);
        }
    }

    /// Withdrawal router: the target is state-derived (owner field), so
    /// NS010 has no caller-chosen target to flag.
    pub fn withdraw(&self, amount: u128) {
        Promise::new(self.owner.clone()).then(
            Self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(25))
                .on_withdraw_result(),
        );
    }

    /// NS004 fix: both promise outcomes handled explicitly.
    #[private]
    pub fn on_deposit_result(&mut self) {
        match env::promise_result(0) {
            PromiseResult::Successful(data) => {
                let amount: u128 = serde_json::from_slice(&data).unwrap_or(0);
                self.balances.insert(&env::current_account_id(), &amount);
            }
            PromiseResult::Failed => {
                env::log_str("deposit failed upstream; no state change");
            }
            _ => {
                env::log_str("unexpected promise result");
            }
        }
    }

    /// NS006 fix: the state write is private to the contract.
    #[private]
    pub fn set_state(&mut self, owner: AccountId) {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "ERR_ONLY_SELF"
        );
        env::state_write(&Self {
            owner,
            staking_pool_allowlist: Vec::new(),
            balances: LookupMap::new(b"b"),
            notes: LookupMap::new(b"n"),
            candidates: Vec::new(),
            pending_withdrawals: Vec::new(),
        });
    }

    /// NS011 fix: every early exit refunds the attached deposit first.
    #[payable]
    pub fn claim(&mut self, reward: u128) {
        if reward > 1_000_000 {
            // Refund before the early exit; a panic would do this
            // automatically, but an early return would not.
            Promise::new(env::predecessor_account_id()).transfer(env::attached_deposit());
            return;
        }
        self.pending_withdrawals.push(reward);
    }

    /// NS009 fix: the winner comes from a revealed commit-reveal secret,
    /// not from predictable block data.
    pub fn draw_winner(&self, reveal: [u8; 32]) -> AccountId {
        let commit = near_sdk::sha256_array(&reveal);
        let index = commit[0] as usize % self.candidates.len();
        self.candidates[index].clone()
    }

    /// NS008 fix: the caller prepays the storage their note consumes
    /// (NEP-145-style storage accounting).
    #[payable]
    pub fn free_note(&mut self, key: String, value: String) {
        let before = env::storage_usage();
        self.notes.insert(&key, &value);
        let added = (env::storage_usage() - before) as u128;
        let cost = env::storage_byte_cost().saturating_mul(added);
        assert!(
            env::attached_deposit() >= cost,
            "attach enough deposit to cover storage"
        );
    }

    /// NS007 fix: bounded iteration (paginated window).
    pub fn total_pending(&self) -> u128 {
        let mut total = 0;
        for amount in self.pending_withdrawals.iter().take(100) {
            total += amount;
        }
        total
    }

    /// NS010 fix: the promise target is allowlist-checked before the
    /// contract pays or calls attacker-chosen accounts.
    pub fn notify_receiver(&self, receiver_id: AccountId, amount: u128) {
        let allowed = self.staking_pool_allowlist.contains(&receiver_id);
        assert!(allowed, "receiver not allowed");
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

    /// NS005 fix: the migration is restricted to the contract itself.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "ERR_ONLY_SELF"
        );
        let old: FixedVault = env::state_read().expect("ERR_CONTRACT_IS_NOT_INITIALIZED");
        Self {
            owner: old.owner,
            staking_pool_allowlist: old.staking_pool_allowlist,
            balances: old.balances,
            notes: old.notes,
            candidates: old.candidates,
            pending_withdrawals: old.pending_withdrawals,
        }
    }
}