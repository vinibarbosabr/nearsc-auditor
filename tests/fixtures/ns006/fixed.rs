/// Fixed: only the contract itself may perform the state write.
#[private]
pub fn force_upgrade(&mut self) {
    let new_state: NewState = env::state_read().expect("current state");
    env::state_write(&new_state);
}
