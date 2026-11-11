---
title: "Potlock audit, Guvenkaya, January 2024"
kind: audit
project: potlock
year: 2024
source: "https://github.com/Guvenkaya/public-reports/blob/master/Potlock-NEAR-Rust-Smart-Contract-Security-Assessment.pdf"
retrieved: 2026-11-11
confidence: verified-public
severity_counts: {"critical":2,"high":2,"medium":1,"low":9,"informational":6}
tags: [public-goods, quadratic-funding, unbounded-iteration, storage-griefing, unchecked-promise-results, dos, state-corruption, storage, access-control]
summary: "Guvenkaya's Potlock review (donation, pot, pot factory, registry, sybil; 4273 LoC): 20 findings - 2 critical (payout DoS via unapproved applications, nested-collection state corruption), 2 high (callback refund misrouting, fee rounding), 13 fixed, 7 acknowledged. Storage accounting and admin/payout flows are the recurring themes. Findings classified per D-017."
---

# Potlock audit, Guvenkaya, January 2024

**Scope:** `PotLock/core` - the donation, pot, pot factory, registry, and sybil
smart contracts on NEAR. 4273 lines of code at baseline commit
`71f35051f81c333c85fafc42d073173191ad14ca`. Review period Jan 4-19, 2024;
final report Jan 30, 2024. 20 findings: 2 critical, 2 high, 1 medium, 9 low,
6 informational; 13 fixed, 7 acknowledged at report time.

## Findings

| ID | Severity | Finding | Status | Vector |
| --- | --- | --- | --- | --- |
| GUV-1 | Critical | DoS of Process Payouts | Fixed | `unbounded-iteration` (NS007) |
| GUV-2 | Critical | State Corruption On Setting Payout | Fixed | `storage-griefing` |
| GUV-3 | High | User Funds Not Returned On Error From Sybil Provider | Fixed | `unchecked-promise-results` (NS004, NS011) |
| GUV-4 | High | Arithmetic Issues In Fee Calculation | Fixed | `uncategorized` (arithmetic/precision; no pattern file yet) |
| GUV-5 | Medium | No Runtime Overflow Checks Applied | Fixed | `uncategorized` (manifest/build level) |
| GUV-6 | Low | Race Condition in Admin Process Payment | Fixed | `async-reentrancy` |
| GUV-7 | Low | Max Project Check Is Invalid | Fixed | `uncategorized` (validation logic) |
| GUV-8 | Low | Deactivating Provider Does Not Remove It From Default Providers | Fixed | `uncategorized` (state consistency) |
| GUV-9 | Low | Deactivated Provider Retains All Stamps | Acknowledged | `uncategorized` (state consistency) |
| GUV-10 | Low | Invalid Implementation Of New Admin Addition | Fixed | `privileged-setter-unguarded` (NS012) |
| GUV-11 | Low | Error-Prone Function Should Be Removed | Acknowledged | `uncategorized` (code quality) |
| GUV-12 | Low | Missing Limits On View Functions | Fixed (partial) | `unbounded-iteration` (NS007) |
| GUV-13 | Low | Privileged Functions Are Not Protected By 2FA | Fixed | `one-yocto-transfer-auth` (NS001) |
| GUV-14 | Low | Privileged Users Should Not Be Allowed To Have Other Roles | Fixed (partial) | `uncategorized` (access-control separation) |
| GUV-15 | Informational | Redundant Functionality | Acknowledged | `uncategorized` |
| GUV-16 | Informational | Size Of The Contract Can Be Decreased | Fixed | `uncategorized` |
| GUV-17 | Informational | Redundant State Statuses | Acknowledged | `uncategorized` |
| GUV-18 | Informational | Usage of assert instead of require | Acknowledged | `uncategorized` |
| GUV-19 | Informational | Using suboptimal panic function | Acknowledged | `uncategorized` |
| GUV-20 | Informational | Redundant state check in initializers | Acknowledged | `uncategorized` |

## Why it matters for nearsc

- GUV-1 is the unbounded-iteration / DoS class nearsc tracks as NS007: a
  public admin flow looping over an attacker-writable collection can be
  bricked by one unapproved entry.
- GUV-2 is nested-collection state corruption after a delete loop, the
  storage-accounting family (NS008, NS006): removing entries from the root
  collection while an inner `UnorderedSet` keeps its own keys leaves the
  contract in an inconsistent state.
- GUV-3 is the callback-refund class (NS004, NS011): the refund target was
  computed from `predecessor_account_id()` inside a `#[private]` callback,
  so failed verification kept user funds in the contract.
- GUV-5 is a build-level rule, not an AST rule: `overflow-checks` was lost
  because the workspace root never inherited the release profile. A scanner
  can only catch this at the manifest level.
- GUV-13 is NS001 territory: privileged functions without
  `assert_one_yocto` are callable via function-call access keys.

## Findings detail (security-relevant)

Classification, impact analysis, and code excerpts are nearsc's, per D-017:
code is quoted from `PotLock/core` (MIT) at the audited commit
`71f35051f81c333c85fafc42d073173191ad14ca`; report prose is paraphrased.
Full finding text, PoCs, and remediation blocks live in the Guvenkaya
report (see Source).

### GUV-1: DoS of Process Payouts (Critical, Fixed)

**Issue.** `admin_process_payouts` loops over every application and asserts
each one is approved. A pending application submitted by any actor before
payout processing makes the whole pass revert, so one attacker-supplied
application can block all payouts until the admin either approves it or the
round stalls.

**Where.** `contracts/pot/src/payouts.rs` (`admin_process_payouts`), audited
commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/payouts.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
for (project_id, v_app) in self.applications_by_id.iter() {
    // TODO: update this to only go through approved applications mapping
    self.assert_approved_application(&project_id);
    // ...if there are payouts for the project...
    if let Some(payout_ids_for_project) = self.payout_ids_by_project_id.get(&project_id) {
        // ...transfer funds...
    }
}
self.all_paid_out = true;
```

**Impact.** Anyone can call `apply` (attacker-writable collection), so a
single unapproved entry on the payout path bricks the payout flow: the admin
is forced to approve a potentially hostile application or halt payouts
entirely.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
the payout loop iterates only approved applications.

**Classification.** Vector `unbounded-iteration`
(`data/patterns/unbounded-iteration.md`); nearsc rule NS007 would flag the
unbounded loop over an attacker-writable collection in a public method.
Report: findings summary and GUV-1 section.

### GUV-2: State Corruption On Setting Payout (Critical, Fixed)

**Issue.** When `chef_set_payouts` resets existing payouts, it removes
payout ids from `payouts_by_id` and the root `payout_ids_by_project_id`
entry, but the nested `UnorderedSet` value is never cleared. Calling
`chef_set_payouts` a second time leaves the collection in an inconsistent
state (the set both looks empty and retains keys), corrupting payout
accounting.

**Where.** `contracts/pot/src/payouts.rs` (`chef_set_payouts`), audited
commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/payouts.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
for application_id in self.approved_application_ids.iter() {
    if let Some(payout_ids_for_application) =
        self.payout_ids_by_project_id.get(&application_id)
    {
        for payout_id in payout_ids_for_application.iter() {
            self.payouts_by_id.remove(&payout_id);
        }
        self.payout_ids_by_project_id.remove(&application_id);
    }
}
```

**Impact.** Deleting a nested collection only through its root entry leaves
orphaned keys inside the inner set; the next write creates a new inner set
while the old entry lingers, so payout state can be double-counted or
silently lost.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
the nested collection is cleared with `.clear()` before removal.

**Classification.** Vector `storage-griefing`
(`data/patterns/storage-griefing.md`), storage-accounting family (NS008;
root-cause overlaps NS006). nearsc NS008 would flag the collection insert /
mutation without storage accounting; the nested-delete hazard itself is a
pattern-class gap worth a dedicated rule (session note).
Report: findings summary and GUV-2 section.

### GUV-3: User Funds Not Returned On Error From Sybil Provider (High, Fixed)

**Issue.** Inside the `#[private]` `sybil_callback`, the refund target is
computed with `env::predecessor_account_id()`. In a callback the
predecessor is the contract itself, so when the sybil verification fails
the deposit is transferred to the contract, not back to the donor.

**Where.** `contracts/pot/src/donations.rs` (`sybil_callback`), audited
commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/donations.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
#[private] // Public - but only callable by env::current_account_id()
pub fn sybil_callback(
    &mut self,
    deposit: Balance,
    // ...args...
    #[callback_result] call_result: Result<bool, PromiseError>,
) -> Promise {
    let caller_id = env::predecessor_account_id();
    if call_result.is_err() {
        // ...
        Promise::new(caller_id).transfer(deposit);
        env::panic_str(
            "There was an error querying sybil check. Donation has been returned to donor.",
        );
    }
    // ...
}
```

**Impact.** Failed cross-contract verification keeps the user's deposit
inside the contract; the "refund" pays the contract itself. Correct
callback plumbing requires passing the donor id as a callback argument.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
the donor id is passed into the callback.

**Classification.** Vector `unchecked-promise-results`
(`data/patterns/unchecked-promise-results.md`); nearsc NS004 covers the
callback-result handling and NS011 the refund path; the
`predecessor_account_id()`-in-callback idiom is the callback-privacy class
(`data/patterns/callback-privacy.md`, NS002 shows the guard).
Report: findings summary and GUV-3 section.

### GUV-4: Arithmetic Issues In Fee Calculation (High, Fixed)

**Issue.** Fee calculation divides before multiplying
(`amount / 10_000 * basis_points`), so small amounts produce zero fees
(full fee bypass) and amounts near the divisor lose precision; rounding
direction is also wrong (protocol fee should round up against itself,
referrer/chef fees round down in the user's favor).

**Where.** `contracts/pot/src/donations.rs` (`calculate_fee`,
`calculate_protocol_fee`, `calculate_referrer_fee`), audited commit
`71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/donations.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
pub(crate) fn calculate_fee(&self, amount: u128, basis_points: u32) -> u128 {
    let total_basis_points = 10_000u128;
    let amount_per_basis_point = amount / total_basis_points;
    basis_points as u128 * amount_per_basis_point
}
```

**Impact.** Fees can be bypassed entirely on small donations and
under-charged generally; the rounding direction leaks value to users (or,
equivalently, away from the protocol) wherever the wrong direction is used.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
multiplication before division, round-down for user-facing fees,
round-up for the protocol fee.

**Classification.** Vector `uncategorized` (arithmetic/precision class has
no pattern file yet; v0.2 candidate). Not AST-detectable without type
inference; a manifest/metadata rule would not cover it either.
Report: findings summary and GUV-4 section.

### GUV-5: No Runtime Overflow Checks Applied (Medium, Fixed)

**Issue.** The `[profile.release]` with `overflow-checks = true` was never
inherited: the workspace root Cargo.toml did not carry the profile, so
compiled contracts shipped without runtime overflow checks (for example,
stamp-count increments in `sybil/src/stamps.rs`).

**Where.** `contracts/pot` workspace `Cargo.toml` (build manifest), audited
commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/Cargo.toml>

**Code (quoted from PotLock/core, MIT).**

```toml
[workspace]
members = [
  "donation",
  "pot",
  "pot_factory",
  "registry",
  "sybil",
  "sybil_provider_simulator"
]
```

**Impact.** Arithmetic overflow wraps silently in release builds; a state
counter can wrap and corrupt accounting in ways the source-level review
believes are panic-safe.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
release profile with overflow checks moved to the root Cargo.toml.

**Classification.** Vector `uncategorized` (build/manifest level; outside
AST reach entirely). Candidate future nearsc surface: manifest lint on
NEAR contract workspaces (session note).
Report: findings summary and GUV-5 section.

### GUV-6: Race Condition in Admin Process Payment (Low, Fixed)

**Issue.** `paid_at` was set inside `transfer_payout_callback`, which
executes blocks after the transfer is initiated. Between initiating and
settling, the same payout still reads as unpaid, so repeated calls to
`admin_process_payouts` could double-pay; `all_paid_out = true` right after
the loop is what made it unexploitable.

**Where.** `contracts/pot/src/payouts.rs` (`admin_process_payouts`,
`transfer_payout_callback`), audited commit
`71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/payouts.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
if payout.paid_at.is_none() {
    // ...transfer funds...
    Promise::new(application.project_id.clone())
        .transfer(payout.amount.0)
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(XCC_GAS)
                .transfer_payout_callback(payout),
        );
}
```

**Impact.** If the guard state moved into the callback (as the PoC shows),
an admin could process the same payouts multiple times during the callback
window.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
`paid_at` is set outside the callback.

**Classification.** Vector `async-reentrancy`
(`data/patterns/async-reentrancy.md`); the cross-receipt window is the
same class nearsc NS004 flags when callback state guards are missing.
Report: findings summary and GUV-6 section.

### GUV-7: Max Project Check Is Invalid (Low, Fixed)

**Issue.** `handle_apply` calls `assert_max_projects_not_reached`, which
counts approved applications; but applications created here are pending,
so the cap never constrains the growing collection of pending applications.

**Where.** `contracts/pot/src/applications.rs` (`handle_apply`) with the
assert in `contracts/pot/src/internal.rs`, audited commit
`71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/applications.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
pub(crate) fn assert_max_projects_not_reached(&self) {
    assert!(
        self.approved_application_ids.len() < self.max_projects.into(),
        "Max projects reached"
    );
}
```

**Impact.** The intended bound on applications is ineffective; the
collection grows unbounded (DoS surface) and the round can be flooded with
pending applications.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
the check moved to `chef_set_application_status`.

**Classification.** Vector `uncategorized` (validation logic: the check
reads the wrong collection; a dataflow rule would need value tracing).
Related DoS surface covered by `unbounded-iteration` (NS007) once the
collection is iterated.
Report: findings summary and GUV-7 section.

### GUV-8: Deactivating Provider Does Not Remove It From Default Providers (Low, Fixed)

**Issue.** `admin_deactivate_provider` flips `is_active` but leaves the id
in `default_provider_ids`, so a deactivated provider keeps serving as a
default until the admin manually resets the default list.

**Where.** `contracts/sybil/src/admin.rs` (`admin_deactivate_provider`),
audited commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/sybil/src/admin.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
#[payable]
pub fn admin_deactivate_provider(&mut self, provider_id: ProviderId) -> Provider {
    self.assert_owner_or_admin();
    if let Some(versioned_provider) = self.providers_by_id.get(&provider_id) {
        let mut provider = Provider::from(versioned_provider);
        provider.is_active = false;
        self.providers_by_id
            .insert(&provider_id, &VersionedProvider::Current(provider.clone()));
        provider
    } else {
        env::panic_str("Provider does not exist");
    }
}
```

**Impact.** Inactive providers remain reachable through the default
provider path; the admin must perform a second manual cleanup, and in the
meantime a dead provider still validates humanity checks.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
deactivation removes the provider from the default list if present.

**Classification.** Vector `uncategorized` (state consistency between two
collections; a cross-collection invariant not expressible as a single-site
AST rule).
Report: findings summary and GUV-8 section.

### GUV-9: Deactivated Provider Retains All Stamps (Low, Acknowledged)

**Issue.** Deactivating a provider leaves every user stamp it issued in
place; the stamps stay valid records even though the provider is no longer
active.

**Where.** `contracts/sybil/src/admin.rs` (`admin_deactivate_provider`),
audited commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/sybil/src/admin.rs>

**Impact.** Users keep credentials from a provider that was removed for
misbehavior; sybil resistance weakens silently.

**Fix.** Acknowledged by the Potlock team (risk accepted, possible
upcoming release).

**Classification.** Vector `uncategorized` (state consistency; same
cross-collection invariant shape as GUV-8).
Report: findings summary and GUV-9 section.

### GUV-10: Invalid Implementation Of New Admin Addition (Low, Fixed)

**Issue.** `owner_set_admins` removes the listed accounts from the admins
set instead of adding them; the setter is a remover.

**Where.** `contracts/pot/src/admin.rs` (`owner_set_admins`), audited
commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/admin.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
pub fn owner_set_admins(&mut self, account_ids: Vec<AccountId>) {
    self.assert_owner();
    for account_id in account_ids {
        self.admins.remove(&account_id);
    }
}
```

**Impact.** Privilege management behaves inversely to its name; an owner
"adding" admins actually strips them, locking out intended operators and
confusing every downstream permission check.

**Fix.** Fixed in [PotLock/core#33](https://github.com/PotLock/core/pull/33):
`remove` replaced with `insert`.

**Classification.** Vector `privileged-setter-unguarded`
(`data/patterns/privileged-setter-unguarded.md`); nearsc NS012 flags the
public `owner_set_*` shape for a predecessor guard; the inverted-operation
semantic itself is a logic bug beyond a single-site AST rule.
Report: findings summary and GUV-10 section.

### GUV-11: Error-Prone Function Should Be Removed (Low, Acknowledged)

**Issue.** `admin_dangerously_set_pot_config` performs a bulk update of the
whole pot configuration in one call; a single malformed transaction can
corrupt many independent settings at once, and dedicated per-field setters
already exist.

**Where.** `contracts/pot/src/admin.rs` (`admin_dangerously_set_pot_config`),
audited commit `71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/admin.rs>

**Impact.** One construction mistake cascades across owner, admins, chef,
timing, providers, and fees simultaneously.

**Fix.** Acknowledged by the Potlock team.

**Classification.** Vector `uncategorized` (API-surface design; code
quality).
Report: findings summary and GUV-11 section.

### GUV-12: Missing Limits On View Functions (Low, Fixed partial)

**Issue.** `get_providers` and `get_default_providers` iterate their whole
collections with no pagination; as the provider set grows, the view can
exceed the gas limit and panic, and any flow consuming it bricks.

**Where.** `contracts/sybil/src/providers.rs` (`get_providers`,
`get_default_providers`), audited commit
`71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/sybil/src/providers.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
pub fn get_providers(&self) -> Vec<ProviderExternal> {
    self.providers_by_id
        .iter()
        .map(|(provider_id, provider)| {
            ProviderExternal::from_provider_id(&provider_id.0, Provider::from(provider))
        })
        .collect()
}
```

**Impact.** Unbounded iteration over a growable collection in a public
method is the canonical NEAR gas-DoS shape.

**Fix.** Partially fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
limits added to `get_providers`.

**Classification.** Vector `unbounded-iteration`
(`data/patterns/unbounded-iteration.md`); nearsc NS007 directly flags the
unbounded `.iter()` over a collection field in a public method.
Report: findings summary and GUV-12 section.

### GUV-13: Privileged Functions Are Not Protected By 2FA (Low, Fixed)

**Issue.** Privileged functions carry no 1-yocto NEAR assertion, so
function-call access keys (used by frontends) can invoke them without a
signature prompt; a compromised frontend key on an owner/admin account can
drive the protocol's admin functions.

**Where.** Pot + sybil admin functions, audited commit
`71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/pot/src/admin.rs>

**Code (quoted from PotLock/core, MIT).**

```rust
pub fn owner_change_owner(&mut self, new_owner: AccountId) {
    self.assert_owner();
    self.owner = new_owner;
}
```

**Impact.** Function-call keys bypass the 2FA signing UX entirely; a
compromised key has full privileged reach with no user confirmation.

**Fix.** Fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
`assert_one_yocto` added to major privileged functions.

**Classification.** Vector `one-yocto-transfer-auth`
(`data/patterns/one-yocto-transfer-auth.md`); nearsc NS001 flags the
missing `assert_one_yocto` on privileged/public state-changing methods.
Report: findings summary and GUV-13 section.

### GUV-14: Privileged Users Should Not Be Allowed To Have Other Roles (Low, Fixed partial)

**Issue.** Owner, admin, and chef accounts can also register as projects,
apply to rounds, and register as providers; role overlap concentrates trust
and enables self-dealing.

**Where.** Registry / pot / sybil registration flows, audited commit
`71f35051f81c333c85fafc42d073173191ad14ca`:
<https://github.com/PotLock/core/blob/71f35051f81c333c85fafc42d073173191ad14ca/contracts/registry/src/lib.rs>

**Impact.** A privileged account can approve its own application or steer
rounds it participates in; misuse risk scales with role count.

**Fix.** Partially fixed in [PotLock/core#32](https://github.com/PotLock/core/pull/32):
pot application restricted from chef/admin/owner.

**Classification.** Vector `uncategorized` (access-control separation;
requires cross-function role reasoning).
Report: findings summary and GUV-14 section.

## Source

Summarized from the public Guvenkaya report:
<https://github.com/Guvenkaya/public-reports/blob/master/Potlock-NEAR-Rust-Smart-Contract-Security-Assessment.pdf>.
Mirror used for retrieval (the as-delivered 61-page edition):
<https://github.com/NEARBuilders/audits/blob/main/Audits/Potlock-NEAR-Rust-Smart-Contract-Security-Assessment-Guvenkaya-Jan-30-2024.pdf>.
See the report for full detail, PoCs, and remediation blocks. Code excerpts
quoted from `PotLock/core` (MIT) at the audited commit; prose is nearsc's
paraphrase per D-014/D-017.
