/// Negative control for the campaign FP (issue #83): near-contract-standards
/// events.rs carries `#[test] fn ft_transfer` fixtures inside `#[cfg(test)]`
/// modules. A test fn is not a callable transfer method; the ABI gate must
/// keep them off the report.
#[cfg(test)]
mod tests {
    #[test]
    fn ft_transfer() {
        let old_owner_id = "bob.near";
        let new_owner_id = "alice.near";
        let amount = 100u128;
        assert!(amount > 0);
        assert_eq!(old_owner_id, "bob.near");
        assert_eq!(new_owner_id, "alice.near");
    }
}
