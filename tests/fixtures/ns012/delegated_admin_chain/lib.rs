/// Fixture host: the PotLock campaign shape (issue #83). The setter lives
/// here; its guard chain lives in `internal.rs` of the same crate.
#[near]
impl Fixture {
    pub fn set_fee(&mut self, fee: u32) {
        self.assert_admin_or_greater();
        self.fee = fee;
    }
}
