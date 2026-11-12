/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Vulnerable: the promise result is assumed successful; a failed
    /// cross-contract call silently advances state.
    pub fn call(&self) -> Promise {
        let account = CALL_TARGETS[0].to_string(); // allowlisted: NS004-only fixture
        Promise::new(account).then(Self::ext(account).on_payout())
    }

    #[private]
    pub fn on_payout(&mut self) {
        if let PromiseResult::Successful(data) = env::promise_result(0) {
            let amount = serde_json::from_slice::<u128>(&data).unwrap_or(0);
            self.paid = amount > 0;
        }
    }
}