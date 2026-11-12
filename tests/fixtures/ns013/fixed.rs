// The fixed shape: the payout draws down the recorded balance in the same
// method (`user.near_amount -= amount` re-booked through `save_user` /
// collection `insert`).
#[near]
impl Fixture {
    #[payable]
    pub fn storage_withdraw(&mut self, amount: Option<u128>) -> u128 {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let mut user = self.internal_get_user(&account_id);
        let available = user.storage_available();
        let amount = amount.unwrap_or(available);
        assert!(amount <= available, "ERR_STORAGE_WITHDRAW_TOO_MUCH");
        user.near_amount -= amount;
        self.save_user(&account_id, user);
        Promise::new(account_id.clone()).transfer(amount).detach();
        self.storage_balance_of(account_id).unwrap()
    }
}
