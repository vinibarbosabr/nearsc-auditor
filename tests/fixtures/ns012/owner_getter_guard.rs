// Owner compared against a getter method call in the body itself (no
// delegated helper): `assert_eq!(env::predecessor_account_id(),
// self.get_owner())` is the same guard as the `self.owner` field shape.
#[near]
impl Fixture {
    pub fn set_fee(&mut self, fee: u32) {
        assert_eq!(
            near_sdk::env::predecessor_account_id(),
            self.get_owner(),
            "ERR_ONLY_OWNER"
        );
        self.fee = fee;
    }

    fn get_owner(&self) -> near_sdk::AccountId {
        self.owner.clone()
    }
}
