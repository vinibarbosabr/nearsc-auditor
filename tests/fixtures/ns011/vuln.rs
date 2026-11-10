/// Payable registration with a late validation and no refund path: if the
/// name is taken, the attached deposit stays in the contract. Storage is
/// prepaid on the records written below, so only NS011 fires.
#[payable]
pub fn register(&mut self, name: String) {
    let paid = env::attached_deposit().as_yoctonear();
    assert!(paid >= self.registration_fee, "underpaid");
    let allowed = self.available_names.contains(&name);
    let required = storage_min_balance();
    assert!(
        paid >= required.as_yoctonear(),
        "storage not covered"
    );
    assert!(
        allowed,
        "name already taken"
    );
    self.taken.insert(&name);
    self.owners.insert(&name, &env::predecessor_account_id());
}
