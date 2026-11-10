use near_sdk::Promise;

const CALL_TARGETS: [&str; 1] = ["example.near"];

/// Fixed: the callback asserts it was called by the contract itself. The
/// promise target is allowlisted so this fixture exercises NS002 only.
pub fn call() -> Promise {
    let account = CALL_TARGETS[0].to_string();
    Promise::new(account).then(on_result)
}

#[private]
pub fn on_result() {
    assert_eq!(
        near_sdk::env::predecessor_account_id(),
        near_sdk::env::current_account_id()
    );
}
