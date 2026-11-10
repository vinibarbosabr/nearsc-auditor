use near_sdk::Promise;

const CALLBACK_TARGETS: [&str; 1] = ["example.near"];

/// Vulnerable: a #[private] callback that can panic on a failed promise.
/// The promise target is allowlisted so this fixture exercises NS003 only.
pub fn call() -> Promise {
    let account = CALLBACK_TARGETS[0].to_string();
    Promise::new(account).then(on_withdraw_result)
}

#[private]
pub fn on_withdraw_result(&mut self) {
    let amount = self.pending.pop().unwrap();
    self.balance += amount;
}
