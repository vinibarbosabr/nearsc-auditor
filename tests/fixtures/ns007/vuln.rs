fn total_pending(&self) -> u128 {
    let mut total = 0;
    for amount in self.pending_withdrawals.iter() {
        total += amount;
    }
    total
}

fn drain_balances(&self) {
    for (account, balance) in self.balances.iter() {
        pay_out(account, balance);
    }
}
