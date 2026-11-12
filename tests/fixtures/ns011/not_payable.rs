// Not payable, and its collection already has its storage covered by a
// storage-economics check at ingestion: no NS011 question applies.
#[near]
impl Fixture {
    pub fn register(&mut self, name: String) {
        if self.seats_remaining == 0 {
            return;
        }
        let required = storage_min_balance();
        assert!(
            env::attached_deposit().as_yoctonear() >= required.as_yoctonear(),
            "storage not covered"
        );
        self.seats_remaining -= 1;
        self.taken.insert(&name);
    }
}