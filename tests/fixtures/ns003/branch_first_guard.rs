use near_sdk::PromiseError;

/// Campaign exemption (issue #83): the PotLock shapes. All three sites are
/// provably Ok-only paths and must not flag.
#[near]
impl Fixture {
    pub fn call(&self) -> near_sdk::Promise {
        near_sdk::Promise::new(near_sdk::env::current_account_id())
            .then(Self::on_result())
    }

    #[private]
    pub fn on_result(
        &mut self,
        #[callback_result] call_result: Result<bool, PromiseError>,
    ) {
        // Alpha: diverging is_err guard, unwrap later in the block.
        if call_result.is_err() {
            near_sdk::env::panic_str("ERR_CALLBACK_FAILED");
        }
        let value = call_result.unwrap();
        self.seen = value;
    }

    #[private]
    pub fn on_result_else(
        &mut self,
        #[callback_result] call_result: Result<bool, PromiseError>,
    ) {
        // Beta: unwrap in the else branch of the guard.
        if call_result.is_err() {
            near_sdk::env::panic_str("ERR_CALLBACK_FAILED");
        } else {
            let value = call_result.unwrap();
            self.seen = value;
        }
    }

    #[private]
    pub fn on_result_or(
        &mut self,
        #[callback_result] call_result: Result<bool, PromiseError>,
    ) {
        // Gamma: unwrap short-circuited behind is_err on the left of ||.
        if call_result.is_err() || !call_result.unwrap() {
            near_sdk::env::panic_str("ERR_CALLBACK_FAILED");
        }
        self.seen = true;
    }
}
