/// Vulnerable: anyone can call `migrate` and replace the contract state.
#[init(ignore_state)]
pub fn migrate() -> Self {
    let old: OldState = env::state_read().expect("old state");
    Self::from(old)
}
