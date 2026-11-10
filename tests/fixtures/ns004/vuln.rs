use near_sdk::Promise;

/// Vulnerable: the promise result is assumed successful; a failed
/// cross-contract call silently advances state.
pub fn call(account: near_sdk::AccountId) -> Promise {
    Promise::new(account).then(Self::ext(account).on_payout())
}

#[private]
pub fn on_payout(&mut self) {
    if let PromiseResult::Successful(data) = env::promise_result(0) {
        let amount = serde_json::from_slice::<u128>(&data).unwrap_or(0);
        self.paid = amount > 0;
    }
}
