// Negative control: delegation to a same-contract internal helper that does
// NOT carry the check must keep flagging. `self.internal_transfer` resolves
// through the existing helper mechanism (no guard in the helper either).
#[near]
impl Fixture {
    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
        self.internal_transfer(
            &near_sdk::env::predecessor_account_id(),
            &receiver_id,
            amount,
        );
    }

    fn internal_transfer(
        &mut self,
        _from: &near_sdk::AccountId,
        _to: &near_sdk::AccountId,
        _amount: u128,
    ) {
    }
}
