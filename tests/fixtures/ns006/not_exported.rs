// Not on the ABI: internal helpers, non-`#[near]` impls, and free fns are
// not attacker-callable, so the same state-write shape there is not an
// NS006 finding. (See vuln.rs for the exported shape.)
#[near]
impl Fixture {
    fn internal_set_state(&mut self, state: NewState) {
        env::state_write(&state);
    }

    pub fn set_state(&mut self, state: NewState) {
        assert_eq!(env::predecessor_account_id(), env::current_account_id());
        self.internal_set_state(state);
    }
}

impl Helper {
    pub fn write_state(state: NewState) {
        env::state_write(&state);
    }
}

pub fn free_write_state(state: NewState) {
    env::state_write(&state);
}