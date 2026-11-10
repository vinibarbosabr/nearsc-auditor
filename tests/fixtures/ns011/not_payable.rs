// Not payable, and its collection already has its storage covered by a
// storage-economics check at ingestion: no NS011 question applies.
pub fn register(&mut self, name: String) {
    assert!(
        self.seats_remaining > 0,
        "sold out"
    );
    let required = storage_min_balance();
    assert!(
        env::attached_deposit().as_yoctonear() >= required.as_yoctonear(),
        "storage not covered"
    );
    self.seats_remaining -= 1;
    self.taken.insert(&name);
}
