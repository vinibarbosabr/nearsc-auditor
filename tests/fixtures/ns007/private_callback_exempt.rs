/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    // A public method that loops over the contract's LookupMap is fine when
    // it is marked private: only the contract itself can invoke it.
    #[private]
    pub fn internal_reindex(&mut self) {
        for (account, balance) in self.balances.iter() {
            self.reindex(account, balance);
        }
    }
}