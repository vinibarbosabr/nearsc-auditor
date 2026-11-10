// The target comes from contract state, not from a caller parameter.
pub fn pay_owner(&self, amount: u128) {
    Promise::new(self.owner.clone()).transfer(near_sdk::NearToken::from_yoctonear(amount));
}
