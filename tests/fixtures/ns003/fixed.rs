use near_sdk::Promise;

const CALL_TARGETS: [&str; 1] = ["example.near"];

/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    /// Fixed: failure is handled explicitly, the callback stays panic-free.
    /// The promise target is allowlisted so this fixture exercises NS003 only.
    pub fn call(&self) -> Promise {
        let account = CALL_TARGETS[0].to_string();
        Promise::new(account).then(Self::on_withdraw_result())
    }

    #[private]
    pub fn on_withdraw_result(&mut self) {
        if let Ok(amount) = serde_json::from_slice::<u128>(&self.result_data) {
            self.balance += amount;
        }
    }
}