use near_sdk::Promise;

/// Fixed: the callback asserts it was called by the contract itself.
pub fn call(account: near_sdk::AccountId) -> Promise {
    Promise::new(account).then(on_result)
}

#[private]
pub fn on_result() {
    assert_eq!(
        near_sdk::env::predecessor_account_id(),
        near_sdk::env::current_account_id()
    );
}
