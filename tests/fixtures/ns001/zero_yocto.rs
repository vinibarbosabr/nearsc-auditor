use near_sdk::NearToken;

/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Vulnerable: only rejects an empty attachment; a function-call access
    /// key with no deposit passes, so the 1-yocto check is still missing.
    pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
        assert!(near_sdk::env::attached_deposit() != NearToken::from_yoctonear(0));
        self.internal_transfer(&near_sdk::env::predecessor_account_id(), &receiver_id, amount);
    }

    fn internal_transfer(&mut self, from: &near_sdk::AccountId, to: &near_sdk::AccountId, amount: u128) {
        // unimplemented helper; the guard above is the only check
    }
}