// Owner-style guard: the setter checks the caller against the on-chain
// owner field. The matcher credits this without #[private].
#[near]
impl Fixture {
    pub fn set_fee(&mut self, fee: u32) {
        assert_eq!(
            near_sdk::env::predecessor_account_id(),
            self.owner,
            "ERR_ONLY_OWNER"
        );
        self.fee = fee;
    }
}