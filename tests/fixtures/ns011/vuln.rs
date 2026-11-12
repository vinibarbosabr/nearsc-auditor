/// A payable method whose early exit keeps the deposit: no panic (which
/// would auto-return the deposit), no refund, no record. Storage is prepaid
/// on the records written below, so only NS011 fires.
#[near]
impl Fixture {
    #[payable]
    pub fn register(&mut self, name: String) {
        let allowed = self.available_names.contains(&name);
        if !allowed {
            env::log_str("name already taken");
            return;
        }
        self.taken.insert(&name);
        self.owners.insert(&name, &env::predecessor_account_id());
    }
}