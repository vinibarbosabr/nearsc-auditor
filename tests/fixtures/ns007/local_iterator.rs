// A loop over a function-local Vec is bounded by the code that builds it;
// callers cannot grow it between calls.
fn snapshot(&self) -> u64 {
    let local: Vec<u64> = vec![1, 2, 3];
    let mut sum = 0;
    for item in &local {
        sum += item;
    }
    sum
}
