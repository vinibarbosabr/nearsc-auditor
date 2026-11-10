// Paginated page: the loop walks at most `limit` entries per call, so gas
// stays bounded no matter how large the collection grows.
fn page(&self, offset: u32, limit: u32) -> u128 {
    let mut total = 0;
    for (i, amount) in self.pending_withdrawals.iter().skip(offset as usize).take(limit as usize).enumerate() {
        if i >= limit as usize {
            break;
        }
        total += amount;
    }
    total
}

// A loop over a fixed, small array is bounded by construction.
fn checksum(&self) -> u32 {
    let mut out = 0u32;
    for byte in [1u8, 2, 3] {
        out = out.wrapping_add(byte as u32);
    }
    out
}
