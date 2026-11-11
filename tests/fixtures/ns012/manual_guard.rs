// Fixed shape: a manual guard the matcher recognizes (both account-id
// calls present in the body).
pub fn set_fee(&mut self, fee: u32) {
    assert_eq!(
        near_sdk::env::predecessor_account_id(),
        near_sdk::env::current_account_id()
    );
    self.fee = fee;
}
