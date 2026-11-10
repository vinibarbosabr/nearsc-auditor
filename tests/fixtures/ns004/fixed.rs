use near_sdk::Promise;

/// Fixed: both the success and the failure arm are handled explicitly.
pub fn call(account: near_sdk::AccountId) -> Promise {
    Promise::new(account).then(Self::ext(account).on_payout())
}

#[private]
pub fn on_payout(&mut self) {
    match env::promise_result(0) {
        PromiseResult::Successful(data) => {
            let amount = serde_json::from_slice::<u128>(&data).unwrap_or(0);
            self.paid = amount > 0;
        }
        PromiseResult::Failed => self.failed = true,
        _ => {}
    }
}
