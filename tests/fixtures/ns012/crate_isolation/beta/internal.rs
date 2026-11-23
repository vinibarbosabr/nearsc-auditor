impl Other {
    fn assert_admin_or_greater(&self) {
        assert!(
            near_sdk::env::predecessor_account_id() == self.owner,
            "Only contract admin or owner can call this method"
        );
    }
}
