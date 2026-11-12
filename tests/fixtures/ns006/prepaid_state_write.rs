// Deposit-funded blob store (the sputnikdao2 `store_blob` shape): the
// caller prepays the exact storage cost of the write, so the direct
// `state_write` is contract-managed storage, not a takeover primitive.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn store_blob() {
    let input = env::input().expect("ERR_NO_INPUT");
    let storage_cost = env::storage_byte_cost().saturating_mul((input.len() + 32) as u128);
    assert!(
        env::attached_deposit() >= storage_cost,
        "ERR_NOT_ENOUGH_DEPOSIT"
    );
    env::state_write(&input);
}