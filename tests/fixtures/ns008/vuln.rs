/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    pub fn register_note(&mut self, key: String, note: String) {
        self.notes.insert(&key, &note);
    }

    pub fn track(&mut self, who: near_sdk::AccountId) {
        self.seen.insert(&who);
    }
}