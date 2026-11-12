/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    // Private callbacks are outside the caller-reachable griefing surface.
    #[private]
    pub fn on_note(&mut self, key: String, note: String) {
        self.notes.insert(&key, &note);
    }
}