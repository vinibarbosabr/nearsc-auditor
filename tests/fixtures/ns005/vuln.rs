/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
/// The init form matters more than the host: `#[init(ignore_state)]`
/// registers `migrate` on the ABI through the init macro.
#[near]
impl Fixture {
    /// Vulnerable: anyone can call `migrate` and replace the contract state.
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let old: OldState = env::state_read().expect("old state");
        Self::from(old)
    }
}