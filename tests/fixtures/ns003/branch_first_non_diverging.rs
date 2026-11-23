use near_sdk::PromiseError;

/// Negative control: the guard's then branch only logs (no panic, no
/// return), so the later unwrap still panics when the result is Err.
/// Must keep flagging.
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
        if call_result.is_err() {
            near_sdk::log_str("callback failed");
        }
        let value = call_result.unwrap();
        self.seen = value;
    }
}
