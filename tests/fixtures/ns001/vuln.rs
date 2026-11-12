/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Vulnerable: the transfer delegates to a helper that also skips the check.
    pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
        self.internal_transfer(&near_sdk::env::predecessor_account_id(), &receiver_id, amount);
    }

    fn internal_transfer(&mut self, from: &near_sdk::AccountId, to: &near_sdk::AccountId, amount: u128) {
        // unimplemented helper; the guard above is the only check
    }
}