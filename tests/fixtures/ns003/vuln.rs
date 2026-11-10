use near_sdk::Promise;

/// Vulnerable: a #[private] callback that can panic on a failed promise.
pub fn call(account: near_sdk::AccountId) -> Promise {
    Promise::new(account).then(on_withdraw_result)
}

#[private]
pub fn on_withdraw_result(&mut self) {
    let amount = self.pending.pop().unwrap();
    self.balance += amount;
}
