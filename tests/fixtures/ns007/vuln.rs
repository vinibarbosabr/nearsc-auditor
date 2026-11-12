/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    pub fn total_pending(&self) -> u128 {
        let mut total = 0;
        for amount in self.pending_withdrawals.iter() {
            total += amount;
        }
        total
    }

    pub fn drain_balances(&self) {
        for (account, balance) in self.balances.iter() {
            pay_out(account, balance);
        }
    }
}