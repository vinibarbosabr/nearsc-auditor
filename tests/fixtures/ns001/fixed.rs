/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Fixed: the transfer asserts the caller attached exactly 1 yoctoNEAR.
    pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
        near_sdk::assert_one_yocto();
        let sender = near_sdk::env::predecessor_account_id();
        self.internal_transfer(&sender, &receiver_id, amount);
    }
}