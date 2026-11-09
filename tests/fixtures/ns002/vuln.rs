use near_sdk::Promise;

/// Vulnerable: `on_result` is used as a callback but is not #[private],
/// so any account can invoke it and fake the callback result.
pub fn call(account: near_sdk::AccountId) -> Promise {
    Promise::new(account).then(on_result)
}

pub fn on_result() {
    // no predecessor check either
}
