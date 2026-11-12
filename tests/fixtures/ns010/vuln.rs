/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    pub fn payout(&self, target: near_sdk::AccountId, amount: u128) {
        Promise::new(target).transfer(near_sdk::NearToken::from_yoctonear(amount));
    }

    pub fn forward(&self, beneficiary: near_sdk::AccountId, amount: u128) {
        let who = beneficiary;
        Promise::new(who).transfer(near_sdk::NearToken::from_yoctonear(amount));
    }
}