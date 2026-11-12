// The let-else abort (panic) is explicit failure handling: the else block
// must diverge, so state can never advance on a `Failed` result. This is
// the shape sputnikdao2's `update` uses; it must not be flagged.
use near_sdk::Promise;

const CALL_TARGETS: [&str; 1] = ["example.near"];

#[near]
impl Fixture {
    pub fn call(&self) -> Promise {
        let account = CALL_TARGETS[0].to_string(); // allowlisted: NS004-only fixture
        Promise::new(account).then(Self::ext(account).on_payout())
    }

    #[private]
    pub fn on_payout(&mut self) {
        let PromiseResult::Successful(data) = env::promise_result(0) else {
            env::panic_str("ERR_NO_RESULT");
        };
        let amount = serde_json::from_slice::<u128>(&data).unwrap_or(0);
        self.paid = amount > 0;
    }
}