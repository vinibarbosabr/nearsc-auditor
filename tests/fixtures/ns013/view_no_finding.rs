// Non-payout endpoints (views, registrations) are outside the rule: no
// `Promise::new(...).transfer(...)` payout in the body, no finding.
#[near]
impl Fixture {
    pub fn storage_balance_of(&self, account_id: near_sdk::AccountId) -> Option<u128> {
        self.internal_get_user_opt(&account_id).map(|user| user.near_amount.as_yoctonear())
    }

    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<near_sdk::AccountId>) -> u128 {
        let deposit_amount = env::attached_deposit();
        let account_id = account_id.unwrap_or_else(env::predecessor_account_id);
        if self.users.contains_key(&account_id) {
            if !deposit_amount.is_zero() {
                Promise::new(env::predecessor_account_id())
                    .transfer(deposit_amount)
                    .detach();
            }
        } else {
            self.internal_register_user(&account_id, deposit_amount);
        }
        0
    }
}
