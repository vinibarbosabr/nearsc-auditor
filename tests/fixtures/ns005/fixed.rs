/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Fixed: the migration asserts it was invoked by the contract itself.
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id()
        );
        let old: OldState = env::state_read().expect("old state");
        Self::from(old)
    }
}