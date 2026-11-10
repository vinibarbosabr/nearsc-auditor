// A public method that loopsover the contract's LookUpMap is fine when it is
// marked private: only the contract itself can invoke it.
#[private]
pub fn internal_reindex(&mut self) {
    for (account, balance) in self.balances.iter() {
        self.reindex(account, balance);
    }
}
