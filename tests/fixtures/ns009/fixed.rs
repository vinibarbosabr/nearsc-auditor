// Commit-reveal: the random value comes from a revealed secret committed
// earlier, so no caller can predict or bias it with block data.
pub fn draw_winner(&self) -> near_sdk::AccountId {
    let reveal = self
        .pending_reveal
        .expect("draw only after a reveal");
    let index = near_sdk::sha256(reveal.as_ref())[0] as usize % self.candidates.len();
    self.candidates[index].clone()
}

// Hashing a secret for integrity is not entropy derivation.
pub fn verify_commit(&self, secret: &[u8], commit: &[u8; 32]) -> bool {
    near_sdk::sha256(secret) == *commit
}
