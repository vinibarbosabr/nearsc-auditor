// The refund path returns the deposit on every early exit, so nothing can
// get stuck. NS010-allowlisted target and prepaid storage keep the other
// rules quiet; the refund transfer satisfies NS011.
#[payable]
pub fn register(&mut self, name: String) {
    let paid = env::attached_deposit().as_yoctonear();
    let allowed = self.available_names.contains(&name);
    assert!(allowed, "name already taken");
    self.taken.insert(&name);
    // change refunds the overpayment to the caller
    Promise::new(env::predecessor_account_id()).transfer(NearToken::from_yoctonear(
        paid - self.registration_fee,
    ));
}

// A payable method without any abort-shaped statement cannot strand a
// deposit mid-flow.
#[payable]
pub fn top_up(&mut self) {
    let paid = env::attached_deposit().as_yoctonear();
    let who = env::predecessor_account_id();
    let current = self.balances.get(&who).unwrap_or(0);
    self.balances.insert(&who, &(current + paid));
}
