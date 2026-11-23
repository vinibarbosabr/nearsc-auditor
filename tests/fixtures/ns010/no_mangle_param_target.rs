/// ABI surface via raw export: a `#[no_mangle]` function taking a
/// caller-chosen promise target must stay flagged.
use near_sdk::Promise;

#[no_mangle]
pub extern "C" fn payout_to(target: near_sdk::AccountId) {
    Promise::new(target);
}
