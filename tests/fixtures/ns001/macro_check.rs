use near_sdk::NearToken;

/// Fixed: the macro statement compares attached_deposit against 1 yoctoNEAR.
pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
    assert!(near_sdk::env::attached_deposit() == NearToken::from_yoctonear(1));
    self.internal_transfer(&near_sdk::env::predecessor_account_id(), &receiver_id, amount);
}

fn internal_transfer(&mut self, from: &near_sdk::AccountId, to: &near_sdk::AccountId, amount: u128) {
    // unimplemented helper; the macro check is the guard
}
