// Timestamps used for bookkeeping (deadlines, ordering) are not a randomness
// verdict; the rule expects a hash-or-modulo sink.
#[near]
impl Fixture {
    pub fn is_sale_open(&self) -> bool {
        env::block_timestamp() < self.sale_deadline
    }

    pub fn event_count(&self) -> u64 {
        self.events.len() as u64
    }
}