use near_sdk::Promise;

const CALLBACK_TARGETS: [&str; 1] = ["example.near"];

/// Fixed: failure is handled explicitly, the callback stays panic-free.
/// The promise target is allowlisted so this fixture exercises NS003 only.
pub fn call() -> Promise {
    let account = CALLBACK_TARGETS[0].to_string();
    Promise::new(account).then(on_withdraw_result)
}

#[private]
pub fn on_withdraw_result(&mut self) {
    if let Ok(amount) = serde_json::from_slice::<u128>(&self.result_data) {
        self.balance += amount;
    }
}
