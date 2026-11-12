// Negative control: a callback parameter named `receiver_id` that steers the
// promise target is NOT exempted by the recorded-predecessor recognition.
// Only `predecessor_account_id`-shaped names count, because only that name
// ties the parameter to the value the contract itself recorded.
#[near]
impl Fixture {
    #[private]
    pub fn on_transfer_result(&mut self, receiver_id: near_sdk::AccountId) -> bool {
        if near_sdk::is_promise_success() {
            true
        } else {
            Promise::new(receiver_id).transfer(near_sdk::NearToken::from_yoctonear(1));
            false
        }
    }
}
