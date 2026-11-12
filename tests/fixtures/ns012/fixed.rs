/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    // Fixed: #[private] asserts the predecessor is the contract itself.
    #[private]
    pub fn set_fee(&mut self, fee: u32) {
        self.fee = fee;
    }
}