/// Negative control for the campaign FP (issue #83): near-contract-standards
/// `utils.rs` ships free `refund_*` helpers whose `account_id` parameter is
/// fed from contract state at every call site. Free functions without a
/// `#[no_mangle]` export are not on the callable surface.
use near_sdk::Promise;

pub fn refund_deposit_to_account(storage_used: u64, account_id: near_sdk::AccountId) {
    let refund = storage_used as u128;
    let _ = account_id;
    let _ = refund;
}

#[near]
impl Fixture {
    pub fn payout(&self, target: near_sdk::AccountId) {
        Promise::new(target);
    }
}
