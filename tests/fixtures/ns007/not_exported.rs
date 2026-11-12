// Not on the ABI: internal helpers and non-`#[near]` impls are not
// attacker-callable, so unbounded loops there are not NS007 findings. (See
// vuln.rs for the exported shape.)
#[near]
impl Fixture {
    fn internal_reindex(&mut self) {
        for (account, balance) in self.balances.iter() {
            self.reindex(account, balance);
        }
    }
}

impl Policy {
    pub fn get_user_roles(&self, user: UserInfo) {
        for role in self.roles.iter() {
            check_role(user, role);
        }
    }
}