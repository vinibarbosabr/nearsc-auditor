// The callback-refund shape: a `#[private]` callback method whose only
// caller-chosen-looking promise target is a parameter that mirrors
// `predecessor_account_id` recorded by this same contract in the initiating
// method (the factory's `create` -> `on_create` refund path). The name
// signals the recorded predecessor, not a caller-chosen target.
#[near]
impl Fixture {
    #[payable]
    pub fn create(&mut self, name: String, args: Vec<u8>) {
        let account_id = near_sdk::env::current_account_id();
        let callback_args = serde_json::to_vec(&serde_json::json!({
            "account_id": account_id,
            "attached_deposit": near_sdk::env::attached_deposit(),
            "predecessor_account_id": near_sdk::env::predecessor_account_id()
        }))
        .expect("Failed to serialize");
        self.factory_manager.create_contract(account_id, &args, "on_create", &callback_args);
    }

    #[private]
    pub fn on_create(
        &mut self,
        account_id: near_sdk::AccountId,
        attached_deposit: near_sdk::NearToken,
        predecessor_account_id: near_sdk::AccountId,
    ) -> bool {
        if near_sdk::is_promise_success() {
            self.daos.insert(&account_id);
            true
        } else {
            Promise::new(predecessor_account_id).transfer(attached_deposit);
            false
        }
    }
}
