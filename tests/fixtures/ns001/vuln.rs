use near_sdk::NearToken;

/// Vulnerable: the transfer delegates to a helper that also skips the check.
pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
    self.internal_transfer(&near_sdk::env::predecessor_account_id(), &receiver_id, amount);
}
