/// Fixture host: a `#[near]` impl so the methods below are on the ABI the
/// way a deployed contract exposes them. Parse-only: `near_sdk` names are
/// resolved by the scanner as tokens, not by rustc.
#[near]
impl Fixture {
    /// Vulnerable: any account can push a new contract state via this endpoint.
    pub fn force_upgrade(&mut self) {
        let new_state: NewState = env::state_read().expect("current state");
        env::state_write(&new_state);
    }
}