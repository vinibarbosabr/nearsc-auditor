use near_sdk::{env, Promise};

/// Protected: `on_result` has no #[private] attribute, but its body asserts
/// that the caller is the contract itself, which is equivalent.
pub fn call(account: near_sdk::AccountId) -> Promise {
    Promise::new(account).then(on_result)
}

pub fn on_result() {
    assert_eq!(
        env::predecessor_account_id(),
        env::current_account_id()
    );
}
