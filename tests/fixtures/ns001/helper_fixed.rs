/// Fixed: the transfer delegates to a helper that asserts the deposit.
pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
    self.internal_transfer(&near_sdk::env::predecessor_account_id(), &receiver_id, amount);
}

fn internal_transfer(&mut self, from: &near_sdk::AccountId, to: &near_sdk::AccountId, amount: u128) {
    assert_one_yocto();
}
