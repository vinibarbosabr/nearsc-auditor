// The sputnikdao-factory2 guard shape: the setter delegates to a same-file
// `assert_owner()` helper whose body compares the predecessor against the
// owner getter (`self.get_owner()`, a method call rather than a field).
// Both the delegated helper and the getter spelling are credited.
#[near]
impl Fixture {
    pub fn set_fee(&mut self, fee: u32) {
        self.assert_owner();
        self.fee = fee;
    }

    pub fn set_limit(&mut self, limit: u32) {
        self.assert_owner();
        self.limit = limit;
    }

    fn assert_owner(&self) {
        assert_eq!(
            self.get_owner(),
            near_sdk::env::predecessor_account_id(),
            "Must be owner"
        );
    }

    fn get_owner(&self) -> near_sdk::AccountId {
        self.owner.clone()
    }
}
