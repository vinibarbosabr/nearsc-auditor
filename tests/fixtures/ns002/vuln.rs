use near_sdk::Promise;

const CALL_TARGETS: [&str; 1] = ["example.near"];

/// Vulnerable: `on_result` is used as a callback but is not #[private],
/// so any account can invoke it and fake the callback result. The promise
/// target is allowlisted here so this fixture exercises NS002 only.
pub fn call() -> Promise {
    let account = CALL_TARGETS[0].to_string();
    Promise::new(account).then(on_result)
}

pub fn on_result() {
    // no predecessor check either
}
