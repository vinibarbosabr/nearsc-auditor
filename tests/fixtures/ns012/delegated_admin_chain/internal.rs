impl Fixture {
    fn assert_admin_or_greater(&self) {
        assert!(
            self.is_owner_or_admin(),
            "Only contract admin or owner can call this method"
        );
    }

    fn is_owner_or_admin(&self) -> bool {
        self.is_owner() || self.is_admin()
    }

    fn is_owner(&self) -> bool {
        near_sdk::env::predecessor_account_id() == self.owner
    }

    fn is_admin(&self) -> bool {
        self.admins.contains(&near_sdk::env::predecessor_account_id())
    }
}
