fn register_note(&mut self, key: String, note: String) {
    self.notes.insert(&key, &note);
}

fn track(&mut self, who: near_sdk::AccountId) {
    self.seen.insert(&who);
}
