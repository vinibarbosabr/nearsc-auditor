/// Isolation control: the helper exists, but in a *different* crate
/// (`beta/`), so it must not credit this crate's setter.
#[near]
impl Fixture {
    pub fn set_fee(&mut self, fee: u32) {
        self.assert_admin_or_greater();
        self.fee = fee;
    }
}
