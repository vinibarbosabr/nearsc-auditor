use near_sdk::NearToken;

/// Vulnerable: NEP-141 transfer without assert_one_yocto, so a function-call
/// access key can move tokens within its method allowance.
pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
    let sender = near_sdk::env::predecessor_account_id();
    self.internal_transfer(&sender, &receiver_id, amount);
}

pub fn internal_transfer(&mut self, from: &near_sdk::AccountId, to: &near_sdk::AccountId, amount: u128) {
    // moves the balance, never asserts the 1-yocto deposit
}
