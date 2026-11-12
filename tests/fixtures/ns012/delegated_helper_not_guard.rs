// Negative control: a `self.assert_*()` call whose same-file helper does
// NOT perform a caller check must not be credited as a guard. `assert_fresh`
// here only validates internal consistency; the setter stays unguarded and
// must keep flagging.
#[near]
impl Fixture {
    pub fn set_fee(&mut self, fee: u32) {
        self.assert_fresh();
        self.fee = fee;
    }

    fn assert_fresh(&self) {
        assert!(self.epoch <= self.current_epoch(), "stale epoch");
    }

    fn current_epoch(&self) -> u64 {
        self.epoch
    }
}
