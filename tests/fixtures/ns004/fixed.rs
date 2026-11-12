use near_sdk::Promise;

const CALL_TARGETS: [&str; 1] = ["example.near"];

/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Fixed: both the success and the failure arm are handled explicitly.
    pub fn call(&self) -> Promise {
        let account = CALL_TARGETS[0].to_string(); // allowlisted: NS004-only fixture
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
}