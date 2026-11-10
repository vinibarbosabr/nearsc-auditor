/// Vulnerable: any account can push a new contract state via this endpoint.
pub fn force_upgrade(&mut self) {
    let new_state: NewState = env::state_read().expect("current state");
    env::state_write(&new_state);
}
