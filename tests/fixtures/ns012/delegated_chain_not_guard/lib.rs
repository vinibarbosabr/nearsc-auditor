/// Negative control: same call shape, but the chain's leaf never checks the
/// caller, so the setter must keep flagging (no over-crediting).
#[near]
impl Fixture {
    pub fn set_fee(&mut self, fee: u32) {
        self.assert_admin_or_greater();
        self.fee = fee;
    }
}
