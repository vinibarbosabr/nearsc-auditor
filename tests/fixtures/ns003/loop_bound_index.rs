/// Campaign exemption (issue #83): `providers[index]` where `index` is the
/// loop variable of `for index in 0..providers.len()` is provably in bounds.
/// The unguarded `items[choice]` from a parameter must keep flagging.
#[near]
impl Fixture {
    pub fn call(&self) -> near_sdk::Promise {
        near_sdk::Promise::new(near_sdk::env::current_account_id())
            .then(Self::on_scores())
            .then(Self::on_choice_fixture())
    }

    #[private]
    pub fn on_scores(&mut self) {
        let providers = vec!["a.near".to_string(), "b.near".to_string()];
        for index in 0..providers.len() {
            let _weight = &providers[index];
        }
    }

    #[private]
    pub fn on_choice_fixture(&mut self) {
        let items = vec!["a".to_string(), "b".to_string()];
        let choice = 1usize;
        let _pick = items[choice];
    }
}
