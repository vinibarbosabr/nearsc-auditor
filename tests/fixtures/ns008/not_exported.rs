// Not on the ABI: internal helpers and non-`#[near]` impls are not
// attacker-callable, so the free insert shape there is not an NS008
// finding. (See vuln.rs for the exported shape.)
#[near]
impl Fixture {
    fn internal_note(&mut self, key: String, note: String) {
        self.notes.insert(&key, &note);
    }
}

impl Policy {
    pub fn track(&mut self, who: near_sdk::AccountId) {
        self.seen.insert(&who);
    }
}