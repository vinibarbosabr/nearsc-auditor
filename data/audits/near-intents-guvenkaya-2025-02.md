---
title: "NEAR Intents audit, Guvenkaya, February-March 2025"
kind: audit
project: near-intents
year: 2025
source: "https://github.com/Guvenkaya/public-reports/blob/master/NEAR-Defuse-Labs-NEAR-Intents-Security-Review.pdf"
retrieved: 2026-11-12
confidence: verified-public
severity_counts: {"critical":0,"high":0,"medium":1,"low":1,"informational":2}
tags: [defi, bridge, intents, unbounded-iteration, key-validation, events]
summary: "Guvenkaya's NEAR Intents review (defuse suite; 103 files, baseline 6da9e2b3): 4 findings - 1 medium (repeating failed intents can steal funds in P2P transfers, scheduled), 1 low (per-user public-key iteration DoS), 2 informational (public-key validation gaps, missing relayer-key events). 0 fixed at report time; all remediation simple. Findings classified per D-017."
---

# NEAR Intents audit, Guvenkaya, February-March 2025

**Scope:** the NEAR Intents smart contracts (the defuse intent-engine suite:
core, crypto, payload, NEP-141/171/245 token flows, relayer keys) across 103
source files, at baseline `6da9e2b3ab598f277d45fb356aee01a5d80ac0a6`.
Review period Feb 12 - Mar 5, 2025; draft report Mar 5, 2025. 4 findings:
0 critical, 0 high, 1 medium, 1 low, 2 informational; 1 scheduled, 3 not
fixed at report time. All remediation complexity simple. Team: Timur
Güvenkaya (principal), Michal Bajor (specialist).

## Findings

| ID | Severity | Finding | Status | Vector |
| --- | --- | --- | --- | --- |
| GUV-1 | Medium | Potential Funds Stealing From Users Via Repeating Failed Intents | Scheduled | `uncategorized` (intent replay across failed receipts; async semantics, no pattern file yet) |
| GUV-2 | Low | Possible DoS Of Public Keys Viewing Per User | Not Fixed | `unbounded-iteration` (NS007) |
| GUV-3 | Informational | Arbitrary Public Key Setting In Privileged Functions | Not Fixed | `uncategorized` (input validation on crypto types) |
| GUV-4 | Informational | Missing Event Emission For Critical Access Control Operations | Not Fixed | `uncategorized` (observability) |

## Why it matters for nearsc

- GUV-2 is NS007 in the wild: `public_keys_of` iterates every public key of
  a user-supplied account with no bound, so one account with many keys can
  gas-DoS the view - and anything off-chain or on-chain that calls it.
- GUV-1 is the sharpest signal for the async model: a user can invalidate a
  signed intent (nonce change, extra failing intent in the array), watch the
  receipt fail, and replay surviving intents while permissive deadlines
  (20s-10min) stay valid. P2P transfers without a TokenDiff zero-check are
  the exploitable shape. This is promise/receipt semantics, not a single
  AST site; nearsc has no rule for it today.
- GUV-3/GUV-4 are hygiene classes (crypto input validation, missing
  access-control events) that scanners should note but not claim to catch.

## Findings detail (security-relevant)

Classification and impact analysis are nearsc's, per D-017. No upstream code
is quoted: the audited codebase's public repository was not located during
the conversion session, so the entry is paraphrase-only (D-017.4 fallback)
and quotes only what the report itself prints. Full finding text and PoCs
are in the report (see Source).

### GUV-1: Potential Funds Stealing From Users Via Repeating Failed Intents (Medium, Scheduled)

**Issue.** A signed intent can be made to fail after signing (nonce
invalidation in a separate transaction, or an extra array element that
drains funds and breaks the token diff). With mainnet deadlines of 20
seconds to 10 minutes, failed intents remain replayable: an attacker (or
the signer) can repeat selected intents, re-sign controlled intents to keep
the token diff balanced, or reconstruct failed intents from chain state.

**Impact.** Funds can be stolen in scenarios where the TokenDiff intent is
not used (for example plain P2P transfers); solvers can lose money or
perform unauthorized operations. Risk stays low with TokenDiff because the
zero-delta constraint is hard to satisfy while changing values.

**Fix.** Scheduled by the NEAR Intents team: document that TokenDiff is the
preferred shape, discourage plain Transfer for swaps, and make explicit that
users are responsible for what they sign.

**Classification.** Vector `uncategorized` (intent replay across failed
receipts; needs promise-flow reasoning, not a single AST site - v0.2
candidate alongside the promise-flow analysis roadmap item). Related class:
`async-reentrancy` covers state between a call and its callback; replay is
the adjacent failure of repeating the call itself.
Report: findings summary and GUV-1.

### GUV-2: Possible DoS Of Public Keys Viewing Per User (Low, Not Fixed)

**Issue.** Accounts can hold unlimited public keys; `public_keys_of`
iterates all of them for a caller-supplied account, so a key-stuffed
account makes the method hit the gas limit. Off-chain components using it
error out; any contract-level use of `iter_public_keys` becomes a protocol
DoS.

**Impact.** Griefing DoS on a view path that takes arbitrary user input;
the collection grows attacker-side at will.

**Fix.** Not fixed at report time. Recommended: cap public keys per
account.

**Classification.** Vector `unbounded-iteration`
(`data/patterns/unbounded-iteration.md`); nearsc NS007 would flag the
unbounded iteration over a user-controlled collection in a public method.
Report: findings summary and GUV-2.

### GUV-3: Arbitrary Public Key Setting In Privileged Functions (Informational, Not Fixed)

**Issue.** Public keys are accepted in several flows
(`add_public_key`/`remove_public_key`, relayer key management, full-access
key management) without format/value validation beyond the SDK's own
`PublicKey` parsing, which accepts weak or degenerate keys; malformed keys
can reach cryptographic operations (signature malleability surface).

**Impact.** Undefined behavior in crypto operations; weak-key injection.

**Fix.** Not fixed at report time. Recommended: comprehensive key
validation at all accepting functions.

**Classification.** Vector `uncategorized` (input validation on crypto
types; not a NEAR-async pattern).
Report: findings summary and GUV-3.

### GUV-4: Missing Event Emission For Critical Access Control Operations (Informational, Not Fixed)

**Issue.** `delete_relayer_key()` and `do_add_relayer_key()` emit no events,
so relayer key-set changes are not auditable off-chain.

**Impact.** Loss of transparency on access-control changes; external
monitors cannot react.

**Fix.** Not fixed at report time. Recommended: event emissions for both
operations.

**Classification.** Vector `uncategorized` (observability; matches the
Hacken/LiNEAR informational on missing privileged-setter events - a
recurring ecosystem hygiene theme).
Report: findings summary and GUV-4.

## Source

Summarized from the public Guvenkaya report (rights-holder copy, sole
public edition found):
<https://github.com/Guvenkaya/public-reports/blob/master/NEAR-Defuse-Labs-NEAR-Intents-Security-Review.pdf>.
Prose is nearsc's paraphrase per D-014/D-017; the report's own code excerpt
is quoted in the vault transcript. No upstream repo was quoted because the
audited repository was not publicly locatable during conversion.

unverified: hidden-hyperlink map - the report's 103 scope paths are
click-through links to the reviewed commit; link targets were not extracted
(no pdfplumber on this machine). Baseline commit and path names verified
from the printed text layer.
