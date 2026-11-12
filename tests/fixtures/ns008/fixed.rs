/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    // #[payable] methods are exempt: every call carries an attached deposit,
    // so the storage the write consumes is paid at call time.
    #[payable]
    pub fn note(&mut self, key: String, value: String) {
        self.notes.insert(&key, &value);
    }

    // A method that checks storage economics first is the intended fix.
    pub fn register(&mut self, who: near_sdk::AccountId) {
        let required = storage_min_balance();
        assert!(
            env::attached_deposit().as_yoctonear() >= required.as_yoctonear(),
            "attach the storage deposit"
        );
        self.seen.insert(&who);
    }
}