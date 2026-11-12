# False positives: policy and handling

> **Status:** shipped policy (2026-11-12, codified after the sputnik-dao-contract live test). How nearsc classifies, discloses, and fixes false positives, and the safety bar every matcher change must clear. This is how the repo works today, not a plan.

## The policy

**nearsc trades precision for recall: a finding you must verify beats a bug you never see.** False positives are handled by disclosure and conservative matcher correction — never by silencing rules, deleting detection, or exempting shapes without proof.

The failure modes of a security scanner are asymmetric. A false positive costs a reviewer minutes, is labeled `heuristic`, and carries a disclaimer on every scan. A false negative can cost a treasury. When the two conflict, nearsc keeps the noise and keeps the disclaimer:

- Heuristic findings are labeled per finding; the text report prints "N of M findings are heuristic-confidence review hints; expect false positives and confirm each one by hand" on every scan.
- `--min-confidence spec` filters the view for spec-backed findings; it never deletes heuristic findings from the record.
- Rules are never removed or disabled to quiet output. The only permitted response to a false-positive class is a matcher correction that clears the safety bar below.

## What is — and is not — a false positive

| Verdict | Meaning |
| --- | --- |
| **True positive** | The flagged code has the bug the rule describes, confirmed by reading the source |
| **Partial true positive** | The class is real but the severity or framing overstates it; kept as a review hint |
| **False positive** | The code is **provably safe from the source**: the guard the rule wants exists in a spelling the matcher does not recognize (a delegated `assert_one_yocto()`, a same-file `assert_owner()` helper, a recorded-predecessor refund path), or the assumed semantics do not apply (NEAR receipts are atomic: a panicking receipt auto-refunds the attached deposit, so NS011 exempts aborts) |

Not a false positive:

- "It looks fine to me" without locating the guard. Unproven safety is an open review item, not an FP.
- "Safe under current deployment/config." Rules reason about code, not deployment.
- "The finding is inconvenient/duplicated/too noisy." That is triage severity, handled by labels and filters — never by matcher changes.

## How nearsc handles FPs today (the shipped mechanisms)

| Mechanism | What it does | Where |
| --- | --- | --- |
| Confidence labels | `spec` vs `heuristic` on every finding and catalog entry | `docs/RULES.md`, `nearsc rules list` |
| Per-scan disclaimer | Text output prints the heuristic count and "confirm each one by hand" | every text report |
| `--min-confidence spec` | Spec-only view without deleting heuristic findings | CLI |
| Per-rule FP notes | Each rule documents its known false-positive shapes and recognized guards | `docs/RULES.md`, per-rule "False positives" |
| Fixture pairs | `vuln.rs` must emit the rule; `fixed.rs` must emit nothing — the oracle that a matcher still fires and does not over-fire | `tests/fixtures/` |
| Negative controls | Fixtures shaped like an FP but carrying the real bug; they must keep flagging | `tests/fixtures/`, e.g. `ns012/delegated_helper_not_guard.rs` |

## The safety bar for matcher changes

Every relaxation of a matcher is a place a real bug can slip through. These rules are non-negotiable for a PR that responds to a false positive:

1. **Provable guard, not probable guard.** Credit only evidence visible in the parsed source: an attribute (`#[private]`), a same-file helper whose body contains the check, an explicit comparison, a documented protocol semantic. A name-based heuristic must be corroborated by a second anchor — NS010's refund exemption requires the `#[private]` attribute *and* the `predecessor_account_id` parameter name; either alone is not enough.
2. **Every relaxation ships a negative control.** A new fixture that resembles the FP shape but is a genuine bug, asserting the rule still fires. No negative control, no merge.
3. **The oracles stay green.** `examples/vulnerable-contract` still emits exactly its seeded findings; `examples/fixed-contract` stays clean; every existing fixture keeps its verdict.
4. **The hardened-reference regression loses nothing real.** The sputnik-dao-contract scan may drop findings only when each dropped finding was individually triaged as a pure FP with file:line evidence. Findings triaged true-positive or partial stay flagged (NS003 on `on_proposal_callback` is the canonical kept finding).
5. **One recognizer per PR.** Each matcher correction lands alone, with its fixtures and its RULES.md note, so any regression attributes to one change.
6. **Never delete a rule to remove noise.** If a rule class is conceptually wrong, that is a design discussion (an ADR), not a quiet detection drop.

**The decision test, in one question:** *could this exemption fire on a version of this code where the guard is absent?* If the answer is not a provable **no**, the fix is rejected and the noise stays.

## Triage workflow for live tests

When you run nearsc against a real contract:

1. **Record the envelope.** Command, nearsc version, target repo and commit. Determinism makes the run reproducible.
2. **Verify every finding by hand.** Open each file:line. Assign the verdict from the table above.
3. **Root-cause every FP before proposing a fix.** Read the matcher (`crates/nearsc/src/rules/<id>.rs`) and name the recognizer gap. A fix without a named gap is a guess; guesses fix FPs by breaking recall.
4. **Record it:** rule id, file:line, verdict, why (the guard/semantics evidence), suggested matcher tweak.
5. **File it.** GitHub issue using the false-positive template, `audit-finding` label.
6. **Fix in order.** Only gaps that clear the safety bar, in the order the bar allows. When in doubt, leave the noise — the disclaimer is the contract with the user.

## Deliberate noise

Some findings stay even when a specific instance looks safe, because the class is real:

- **NS003 on sputnikdao2 `on_proposal_callback`** — `.expect("ERR_NO_PROPOSAL")` in a `#[private]` callback; safe by construction except under a remove-mid-flight race. Kept: panic-in-callback is exactly the class the rule exists for.
- Payout routers whose purpose is paying caller-specified accounts stay heuristic NS010 hints until v0.2 dataflow can bind amounts to state.

If a kept-noise class is ever judged wrong, the remedy is a documented ADR amendment — never a silent exemption.

## Community reports

Use the false-positive issue template (`.github/ISSUE_TEMPLATE/false-positive.md`, `audit-finding` label). A good report:

- pins the nearsc version and the target commit,
- quotes the finding line and the guard that makes the code safe,
- includes a minimal fixture-shaped snippet when possible — accepted FPs become negative-control fixtures.

What happens next: a maintainer re-verifies from source and returns a verdict (TP / partial / FP). Accepted FPs become matcher-fix candidates, prioritized by how many reports hit the same shape. Every fix lands under the safety bar above.

## Worked example: the sputnik-dao-contract campaign

The policy was codified from this campaign (snapshot git `5434a59`, 2026-11-12; target: sputnikdao2, factory2, staking, test-token):

| nearsc | Findings | What changed |
| --- | --- | --- |
| v0.1.0 | 29 (critical 1, high 4, medium 18, low 6) | Manual triage: 25 FP-class, 3 partial TPs — and the strongest real bug in the snapshot (a repeatable `storage_withdraw` drain) sat **outside the rule set entirely** |
| v0.1.1 (`de19b22`) | 6 (high 3, medium 3) | ABI gate + matcher corrections; the 23 pure FPs dropped |
| v0.1.2 (`0bb3c45`) | 2 (high 1, medium 1) | The 5 residual FPs (trait delegation ×2, delegated owner guard ×2, recorded-predecessor refund ×1) fixed under the safety bar; NS013 added — the drain now **is** a finding |

The regression that matters: across both fixes, no finding triaged true-positive or partial was ever dropped. Final envelope: the real drain (NS013) plus the one deliberate review hint (NS003). Zero false positives on a hardened, in-production codebase — with recall strictly higher than where the campaign started.
