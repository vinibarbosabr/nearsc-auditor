// The refund path returns the deposit on every early exit, so nothing can
// get stuck. The refund transfer satisfies NS011.
#[near]
impl Fixture {
    #[payable]
    pub fn register(&mut self, name: String) {
        let paid = env::attached_deposit().as_yoctonear();
        let allowed = self.available_names.contains(&name);
        if !allowed {
            Promise::new(env::predecessor_account_id())
                .transfer(NearToken::from_yoctonear(paid));
            return;
        }
        self.taken.insert(&name);
    }

    // A payable method without an early exit cannot strand the deposit
    // mid-flow: every path records the value the caller sent.
    #[payable]
    pub fn top_up(&mut self) {
        let paid = env::attached_deposit().as_yoctonear();
        let who = env::predecessor_account_id();
        let current = self.balances.get(&who).unwrap_or(0);
        self.balances.insert(&who, &(current + paid));
    }
}