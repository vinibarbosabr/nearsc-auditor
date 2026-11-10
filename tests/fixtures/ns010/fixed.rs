// Allowlist check before the promise target is used: the caller can only
// pick among accounts the contract already trusts.
pub fn payout(&self, beneficiary: near_sdk::AccountId, amount: u128) {
    require!(
        self.allowlist.contains(&beneficiary),
        "beneficiary not allowed"
    );
    Promise::new(beneficiary).transfer(near_sdk::NearToken::from_yoctonear(amount));
}

// A self-promise (the contract calling itself) carries no new trust boundary.
pub fn notify_self(&self, amount: u128) {
    Promise::new(env::current_account_id()).transfer(near_sdk::NearToken::from_yoctonear(amount));
}

// Literal targets are fully determined by the code, not the caller.
pub fn ping_factory(&self) {
    Promise::new("factory.near".to_string()).transfer(near_sdk::NearToken::from_yoctonear(1));
}
