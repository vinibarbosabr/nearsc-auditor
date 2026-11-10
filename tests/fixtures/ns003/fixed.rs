use near_sdk::Promise;

/// Fixed: failure is handled explicitly, the callback stays panic-free.
pub fn call(account: near_sdk::AccountId) -> Promise {
    Promise::new(account).then(on_withdraw_result)
}

#[private]
pub fn on_withdraw_result(&mut self) {
    if let PromiseResult::Successful(data) = env::promise_result(0) {
        if let Ok(amount) = serde_json::from_slice::<u128>(&data) {
            self.balance += amount;
        }
    }
}
