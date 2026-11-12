use near_sdk::NearToken;

/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Fixed: the 1-yocto check wrapped in an `if` (panic on mismatch) is a
    /// recognized guard.
    pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
        if near_sdk::env::attached_deposit() != NearToken::from_yoctonear(1) {
            near_sdk::env::panic_str("attached deposit must be exactly 1 yoctoNEAR");
        }
        self.internal_transfer(&near_sdk::env::predecessor_account_id(), &receiver_id, amount);
    }

    fn internal_transfer(&mut self, from: &near_sdk::AccountId, to: &near_sdk::AccountId, amount: u128) {
        // unimplemented helper; the guard above is the only check
    }
}