use near_sdk::Promise;

const CALL_TARGETS: [&str; 1] = ["example.near"];

/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
/// `manual_guard` has no `#[private]` attribute; its body asserts the
/// caller is the contract itself, which is equivalent.
#[near]
impl Fixture {
    /// Protected: manual guard. The promise target is allowlisted so this
    /// fixture exercises NS002 only.
    pub fn call(&self) -> Promise {
        let account = CALL_TARGETS[0].to_string();
        Promise::new(account).then(Self::on_result())
    }

    pub fn on_result(&mut self) {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id()
        );
    }
}