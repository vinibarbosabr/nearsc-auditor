// Not on the ABI: internal helpers and non-`#[near]` impls are not
// attacker-callable, so the setter-named shape there is not an NS012
// finding. (See vuln.rs for the exported shape.)
#[near]
impl Fixture {
    fn internal_set_fee(&mut self, fee: u32) {
        self.fee = fee;
    }
}

impl Policy {
    pub fn update_fee(&mut self, fee: u32) {
        self.fee = fee;
    }
}