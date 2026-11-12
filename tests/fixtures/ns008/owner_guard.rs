// Owner-style guard: the caller must be the trusted staking contract (a
// state-derived local), so the storage write is not attacker-funded. This
// is the sputnikdao2 `delegate`/`undelegate` shape.
#[near]
impl Fixture {
    pub fn delegate(&mut self, account_id: &near_sdk::AccountId, amount: u128) {
        let staking_id = self.staking_id.clone().expect("ERR_NO_STAKING");
        assert_eq!(
            env::predecessor_account_id(),
            staking_id,
            "ERR_INVALID_CALLER"
        );
        self.delegations.insert(account_id, &(amount + 1));
    }
}