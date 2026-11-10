// Writes to a local map are never the contract's storage: nothing reaches
// the persistent state, so there is nothing to grief.
fn dedupe(&self, events: &Vec<String>) -> usize {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for event in events {
        seen.insert(event);
    }
    seen.len()
}
