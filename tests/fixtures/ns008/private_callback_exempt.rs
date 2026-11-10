// Private callbacks are outside the caller-reachable griefing surface.
#[private]
fn on_note(&mut self, key: String, note: String) {
    self.notes.insert(&key, &note);
}
