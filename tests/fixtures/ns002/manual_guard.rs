use near_sdk::{env, Promise};

const CALL_TARGETS: [&str; 1] = ["example.near"];

/// Protected: `on_result` has no #[private] attribute, but its body asserts
/// that the caller is the contract itself, which is equivalent. The promise
/// target is allowlisted so this fixture exercises NS002 only.
pub fn call() -> Promise {
    let account = CALL_TARGETS[0].to_string();
    Promise::new(account).then(on_result)
}

pub fn on_result() {
    assert_eq!(
        env::predecessor_account_id(),
        env::current_account_id()
    );
}
