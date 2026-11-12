// Panicking exits do not strand the deposit: the receipt reverts and the
// deposit auto-returns to the caller (the KB pattern documents this). So a
// payable method whose only failure mode is a panic/abort is NOT a finding.
#[near]
impl Fixture {
    #[payable]
    pub fn register(&mut self, name: String) {
        let paid = env::attached_deposit().as_yoctonear();
        assert!(paid >= self.registration_fee, "underpaid");
        assert!(self.available_names.contains(&name), "name already taken");
        self.taken.insert(&name);
        self.owners.insert(&name, &env::predecessor_account_id());
    }
}