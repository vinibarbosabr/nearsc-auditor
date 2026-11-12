/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    // A state_write body is NS006's verdict, not NS012's: the deferral
    // keeps one access-control bug on one rule.
    pub fn set_admin(&mut self, admin: near_sdk::AccountId) {
        near_sdk::env::state_write(&Self { admin });
    }
}