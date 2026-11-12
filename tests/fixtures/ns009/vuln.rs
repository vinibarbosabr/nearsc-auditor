/// Fixture host: a `#[near]` impl so the methods below are on the ABI.
#[near]
impl Fixture {
    pub fn draw_winner(&self) -> near_sdk::AccountId {
        let index = (env::block_index() as u128 + env::block_timestamp() as u128)
            % self.candidates.len() as u128;
        self.candidates[index as usize].clone()
    }

    pub fn lucky_number(&self) -> u128 {
        let seed = near_sdk::_hash(b"") ;
        near_sdk::sha256(env::block_timestamp().to_le_bytes().as_ref())[0] as u128
    }
}