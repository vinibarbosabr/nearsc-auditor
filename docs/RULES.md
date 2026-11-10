# Rules

> **Status:** specification for v0.1 (2026-11-10). Rule ids, severities, and detection notes are final unless the build proves a rule infeasible. Per-rule status is labeled in each section: NS001-NS006 have shipped matchers today. Every rule ships with a vulnerable and a patched fixture; the fixture pair is the test oracle. `nearsc rules list` / `nearsc rules show <id>` render the catalog from the binary.

Severity scale: **critical** (direct loss of funds or full takeover), **high** (exploitable with realistic preconditions), **medium** (griefing, stuck funds, broken invariants), **low** (hardening), **info** (review hint). Confidence: **spec** (standard or documented semantics), **heuristic** (pattern-based, needs review).

Machine-readable metadata lives in `rules/<ID>.toml` (**planned, lands with the `v0.1.0` tag**, see [ARCHITECTURE.md](ARCHITECTURE.md)); until then this page is the source of truth for ids, severities, and detection notes. The binary renders `nearsc rules list` / `nearsc rules show <id>` from the `CATALOG` table in `crates/nearsc/src/rules/mod.rs`, which the catalog/matcher parity test in the same file keeps in sync with the registered matchers.

---

## NS001: one-yocto-missing-on-transfer

- **Status:** shipped · **Matcher:** `one_yocto_missing`
- **Severity:** high · **Confidence:** spec · **Tags:** nep-141, nep-171, authorization
- **Detects:** implementations of `ft_transfer`, `ft_transfer_call`, `nft_transfer`, `nft_transfer_call` that do not enforce a 1-yoctoNEAR attached deposit (`assert_one_yocto()` or an equivalent check).
- **Why it matters:** the NEP-141/171 transfer methods are specified to require exactly 1 yoctoNEAR so the call must be authorized with a full-access key. A function-call access key cannot attach a deposit, so the check prevents key-scoped abuse. Omitting it is a spec violation and a real authorization gap.
- **Detection:** find trait impl methods with those names; check the body for `assert_one_yocto`, `attached_deposit() == 1`, or a shared helper call.

```rust
// vulnerable: any function-call key can move tokens
pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0);
}
```

```rust
// fixed
pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
    assert_one_yocto();
    self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0);
}
```

- **False positives:** wrappers that call a helper which asserts the deposit; the matcher follows one level of local helper calls. **Recognized guards:** `assert_one_yocto` (call or macro), an `attached_deposit` comparison against the literal `1` or a `from_yoctonear(1)`-style call, or a same-file helper that performs one of those. 1-yocto comparisons inside `assert!`/`assert_eq!`/`require!` are recognized token-wise; a zero-yocto comparison (`!= from_yoctonear(0)`) is **not** a guard.
- **Refs:** [NEP-141 core](https://nomicon.io/Standards/Tokens/FungibleToken/Core), [NEP-171 core](https://nomicon.io/Standards/Tokens/NonFungibleToken/Core), [NEAR access keys](https://docs.near.org/protocol/accounts-contracts/access-keys)

---

## NS002: callback-not-private

- **Status:** shipped · **Matcher:** `callback_not_private`
- **Severity:** high · **Confidence:** spec · **Tags:** async, callbacks, access-control
- **Detects:** a function used as a `.then()` callback, or annotated `#[callback]`/`#[callback_result]`/`#[callback_unwrap]`/`#[callback_vec]`, that is not annotated `#[private]` and has no recognized manual guard.
- **Why it matters:** any account can call a public method. Without `#[private]` (which asserts `predecessor == current_account_id`), an attacker can invoke the callback directly and fake a successful cross-contract result, corrupting state or releasing funds.
- **Detection:** collect callback names from `.then(...)` call sites and `#[callback*]` attributes **in the same file**; resolve against functions defined in that file; pass when the function has `#[private]`, mentions both `predecessor_account_id` and `current_account_id` in its body, or invokes an `assert_self`-style macro. Cross-file callback resolution is on the v0.2 roadmap.

```rust
// vulnerable
pub fn on_withdraw(&mut self, amount: U128) {
    self.internal_release(amount.0); // attacker can call this directly
}
```

```rust
// fixed
#[private]
pub fn on_withdraw(&mut self, amount: U128) {
    self.internal_release(amount.0);
}
```

- **False positives:** a callback whose guard lives behind a helper or a macro that does not name both account-id calls in its tokens is still flagged. The matcher recognizes `#[private]`, manual `predecessor_account_id` + `current_account_id` checks, and `assert_self`-style macros; it does not expand other macros.
- **Refs:** [NEAR access keys](https://docs.near.org/protocol/accounts-contracts/access-keys), [near-sdk-rs](https://github.com/near/near-sdk-rs)

---

## NS003: callback-panic-risk

- **Status:** shipped · **Matcher:** `callback_panic`
- **Severity:** medium · **Confidence:** heuristic · **Tags:** async, callbacks, robustness
- **Detects:** `unwrap()`, `expect()`, `panic!`, or unchecked slice indexing inside `#[private]` callback functions.
- **Why it matters:** a panic in a callback aborts the receipt. Funds and state can be left in a half-updated condition, and retries are not automatic. Callbacks should handle failure explicitly and stay panic-free.
- **Detection:** AST walk of callback bodies for the listed expressions.
- **False positives:** `unwrap` on values proven infallible in the same scope; the rule reports as medium and the message asks for review.

```rust
#[private]
pub fn on_swap(&mut self) {
    let result = env::promise_result(0);
    let amount: u128 = result.unwrap().try_into().unwrap(); // panics on failure
    self.balance += amount;
}
```

```rust
#[private]
pub fn on_swap(&mut self) {
    if let PromiseResult::Successful(data) = env::promise_result(0) {
        if let Ok(amount) = serde_json::from_slice::<U128>(&data) {
            self.balance += amount.0;
        }
    }
}
```

- **Refs:** [near-sdk-rs](https://github.com/near/near-sdk-rs), [NEAR docs](https://docs.near.org/)

---

## NS004: unchecked-promise-result

- **Status:** shipped · **Matcher:** `unchecked_promise_result`
- **Severity:** high · **Confidence:** heuristic · **Tags:** async, promises
- **Detects:** functions that consume a promise result (call `env::promise_result` or name `PromiseResult`) without a `PromiseResult::Failed` match or `if let ... Failed` arm.
- **Amended scope (2026-11-10):** `#[callback*]`-deserialized parameters are **not** flagged. The near-sdk macros unwrap and panic on failure by design; that is documented semantics, not a finding, and flagging it would mark idiomatic code. Review callbacks that rely on the macro behavior where a silent failure corrupts state.
- **Why it matters:** cross-contract calls fail. Code that assumes success updates state on a lie; code that panics on failure can brick flows. Both are common and both are detectable.
- **Detection:** functions whose bodies call `env::promise_result` or mention `PromiseResult` without a `Failed` arm in a `match` or `if let`.

```rust
#[private]
#[callback]
pub fn on_payout(&mut self) {
    let amount = env::promise_result(0); // #[callback] already panics on failure
    self.paid = true;
}
```

```rust
#[private]
pub fn on_payout(&mut self) {
    match env::promise_result(0) {
        PromiseResult::Successful(_) => self.paid = true,
        PromiseResult::Failed => self.failed = true,
        _ => {}
    }
}
```

- **False positives:** callbacks that intentionally abort on failure by design, documented as such.
- **Refs:** [near-sdk-rs promises](https://github.com/near/near-sdk-rs)

---

## NS005: init-ignore-state-unguarded

- **Status:** shipped · **Matcher:** `init_ignore_state`
- **Severity:** critical · **Confidence:** heuristic · **Tags:** init, migrate, access-control
- **Detects:** `#[init(ignore_state)]` functions or migrate-style functions that do not assert the predecessor is the owner or the contract itself.
- **Why it matters:** `#[init(ignore_state)]` skips the "state must not exist" check. A public migrate method without access control lets any account overwrite contract state.
- **Detection:** attribute scan plus body check for predecessor assertions.

```rust
// vulnerable: anyone can reinitialize
#[init(ignore_state)]
pub fn migrate() -> Self {
    let old: OldState = env::state_read().unwrap();
    Self::from(old)
}
```

```rust
// fixed
#[init(ignore_state)]
pub fn migrate() -> Self {
    assert_eq!(env::predecessor_account_id(), env::current_account_id());
    let old: OldState = env::state_read().unwrap();
    Self::from(old)
}
```

- **Refs:** [near-sdk-rs](https://github.com/near/near-sdk-rs), [NEAR docs](https://docs.near.org/)

---

## NS006: upgrade-path-unguarded

- **Status:** shipped · **Matcher:** `upgrade_path`
- **Severity:** critical · **Confidence:** heuristic · **Tags:** upgrade, access-control
- **Detects:** direct `state_write` / `env::state_write` calls, or migrate deserialization patterns, reachable from a public method without an owner or self check.
- **Why it matters:** state writes bypass the normal storage model and are the last step of an upgrade. If an attacker can reach one, they own the contract.
- **Detection:** call-site scan for state write APIs; walk up to the enclosing public function; check for predecessor/owner assertions. **v0.1 scope:** direct `state_write` call sites in unguarded functions only; migrate-deserialization reachability lands with dataflow analysis in v0.2.
- **Refs:** [near-sdk-rs](https://github.com/near/near-sdk-rs)

---

## NS007: unbounded-iteration

- **Status:** shipped · **Matcher:** `unbounded_iteration`
- **Severity:** medium · **Confidence:** heuristic · **Tags:** gas, griefing
- **Detects:** `for` loops over `self`-rooted collection fields in public methods (direct, borrowed, or via `.iter()`/`.into_iter()`/`.keys()`/`.values()`/`.iter_from()`/`.drain()`) where the collection can grow from user input, without pagination bounds.
- **Why it matters:** NEAR gas is finite per receipt. An unbounded loop that grows with users eventually makes the method uncallable, locking funds or governance actions.
- **Detection:** AST walk of `for` loops in public, non-`#[init]`, non-`#[private]` methods. v0.1 scope: the iterable must be rooted at `self` (`self.field`, `&self.field`, `self.field.iter()`, chains of such calls) so the reported loop is over state callers can grow; loops over function-local collections are not flagged. A bounded window (`.skip(offset).take(limit)`) removes the finding, as does manual `break` bounding.
- **False positives:** a self-collection whose growth is capped by ingestion limits elsewhere; the message asks for pagination evidence before you dismiss it.
- **Refs:** [NEAR docs](https://docs.near.org/)

---

## NS008: storage-griefing

- **Status:** shipped · **Matcher:** `storage_griefing`
- **Severity:** medium · **Confidence:** heuristic · **Tags:** storage, griefing
- **Detects:** `insert`/`set`/`insert_id`/`insert_checked` calls rooted at `self` collections in public, non-`#[payable]` methods whose body never mentions `attached_deposit` or a storage-management check.
- **Why it matters:** storage costs NEAR. A method that stores attacker-controlled data for free lets an attacker drain the contract's balance through storage stake.
- **Detection:** AST scan for collection writes rooted at `self` (LookupMap, UnorderedMap, TreeMap, Vector, LookupSet method shapes) inside public methods. Exemptions: `#[private]` callbacks, `#[init]`, `#[payable]` (deposit accompanies every call), and bodies mentioning `attached_deposit`, `storage_usage`, `storage_min_balance`, `unregister`, `storage_byte_cost`, or `required_deposit` (token-based scan, macro groups included). Writes to function-local maps are never flagged: only persistent `self.` state is contract storage.
- **False positives:** collections whose growth is self-funded by an internal accounting elsewhere; the message asks for the deposit path before you dismiss it.
- **Refs:** [NEAR docs](https://docs.near.org/)

---

## NS009: insecure-randomness

- **Status:** shipped · **Matcher:** `insecure_randomness`
- **Severity:** medium · **Confidence:** heuristic · **Tags:** randomness
- **Detects:** entropy derived from `block_index` or `block_timestamp` inside a hash-shaped call (`sha256`, `keccak`, `hash*`) or a `%`-modulo selection.
- **Why it matters:** block data is predictable or influenceable. Lotteries, NFT minting, and shuffles built on it are exploitable.
- **Detection:** value-flow-by-shape: the probe tracks whether expression context is "inside a hash call" or "inside a `%` expression"; a predictable call (`block_index`, `block_timestamp`) encountered there is the finding (reported at the call site). Timestamp comparisons for deadlines/bookkeeping pass. Commit-reveal (hashing a revealed secret) is the fixed shape and hashes of caller secrets pass.
- **False positives:** modulo arithmetic on user-sized counters that never sees block data; hash uses where the hashed input is a secret, not environment data.
- **Refs:** [NEAR randomness](https://docs.near.org/smart-contracts/security/random)

---

## NS010: arbitrary-promise-target

- **Status:** shipped · **Matcher:** `arbitrary_promise_target`
- **Severity:** high · **Confidence:** heuristic · **Tags:** promises, access-control
- **Detects:** `Promise::new(<param>)` where the target is a method parameter (or a `let`-bound alias of one), without an allowlist check.
- **Why it matters:** an attacker-controlled promise target lets a caller make the contract call arbitrary contracts, often combined with attached funds.
- **Detection:** the walk collects `Promise::new` call sites (2-segment paths, macro shapes included) and checks the argument against the method's parameter names (plus `let`-bound aliases). Recognized release valves: a body mention of `allowlist`/`allowed`/`contains` (token scan, macro groups included) or a full owner guard (`body_has_guard`). Literal targets, `env::current_account_id()`, and state-derived fields pass because they are not parameters.
- **False positives:** escrows and routers whose entire purpose is to pay caller-specified accounts with caller-supplied funds; NEP-141 `ft_transfer`-style methods that move only the earned balance: pair the flag with the authorization facts before you dismiss it.
- **Refs:** [NEAR docs](https://docs.near.org/smart-contracts/anatomy/actions)

---

## NS011: deposit-refund-missing

- **Status:** spec, matcher planned Wed 2026-11-11 (NS007-NS012 batch)
- **Severity:** low · **Confidence:** heuristic · **Tags:** deposits, refunds
- **Detects:** payable functions that can return early (via `assert!`/`require!` after deposit acceptance) without a refund path.
- **Why it matters:** attached deposits can get stuck in the contract when a validation fails after the deposit is accepted. Users lose funds silently.
- **Detection:** payable attribute plus early-return assertion scan; check for `Promise::new(predecessor).transfer(...)`.
- **Refs:** [NEAR docs](https://docs.near.org/)

---

## NS012: privileged-setter-unguarded

- **Status:** spec, matcher planned Wed 2026-11-11 (NS007-NS012 batch)
- **Severity:** medium · **Confidence:** heuristic · **Tags:** access-control
- **Detects:** public methods named `set_*`, `update_*`, `pause_*`, `withdraw_*`, `admin_*` without a predecessor assertion or owner macro.
- **Why it matters:** naming conventions reveal intent. A setter without a guard is either a bug or a missing macro; either way it deserves review.
- **Detection:** name pattern plus body check for predecessor assertions.
- **False positives:** intentional public configuration methods; the rule is medium and the message asks for review.
- **Refs:** [NEAR access keys](https://docs.near.org/protocol/accounts-contracts/access-keys)

---

## Finding shape

Real output from `cargo run -p nearsc -- scan examples/vulnerable-contract --format json` (2026-11-10):

```json
{
  "rule_id": "NS002",
  "title": "Callback not marked #[private]",
  "severity": "high",
  "confidence": "spec",
  "file": "src/lib.rs",
  "line": 50,
  "column": 12,
  "snippet": "pub fn on_deposit_complete(&mut self, amount: u128) {",
  "message": "callback `on_deposit_complete` can be invoked by any account; add #[private] or assert predecessor == current_account_id",
  "refs": [
    "https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md"
  ]
}
```

The full envelope holds 6 findings (2 critical, 3 high, 1 medium) plus the header fields; see the scan envelope paragraph below.

Scan envelope: `tool`, `version`, `target`, `summary` (counts per severity), `findings`, `parse_errors`. No `generated_at`: findings and the envelope are byte-stable for the same input (determinism contract). `generated_at` is not planned to return inside findings; if an envelope-level timestamp is ever added it will be CLI-layer only, opt-in.

## Adding a rule

See [CONTRIBUTING.md](CONTRIBUTING.md). Rules without a fixture pair and a `fixed` snippet are not accepted.
