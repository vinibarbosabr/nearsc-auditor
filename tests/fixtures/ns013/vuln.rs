// The S-1 / issue #239 shape: `storage_withdraw` pays out the recorded
// available balance and never reduces `user.near_amount` (or re-books the
// user record), so the same credit is withdrawable on every call.
#[near]
impl Fixture {
    #[payable]
    pub fn storage_withdraw(&mut self, amount: Option<u128>) -> u128 {
        assert_one_yocto();
        let account_id = env::predecessor_account_id();
        let user = self.internal_get_user(&account_id);
        let available = user.storage_available();
        let amount = amount.unwrap_or(available);
        assert!(amount <= available, "ERR_STORAGE_WITHDRAW_TOO_MUCH");
        Promise::new(account_id.clone()).transfer(amount).detach();
        self.storage_balance_of(account_id).unwrap()
    }
}
