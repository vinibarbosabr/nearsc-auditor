---
title: "Potlock audit, Guvenkaya, January 2024"
kind: audit
project: potlock
year: 2024
source: "https://github.com/Guvenkaya/public-reports/blob/master/Potlock-NEAR-Rust-Smart-Contract-Security-Assessment.pdf"
retrieved: 2026-11-11
confidence: verified-public
severity_counts: {"critical":2,"high":2,"medium":1,"low":9,"informational":6}
tags: [public-goods, quadratic-funding, dos, state-corruption, arithmetic, storage, access-control]
summary: "Guvenkaya's Potlock review (donation, pot, pot factory, registry, sybil; 4273 LoC): 20 findings - 2 critical (payout DoS via unapproved applications, nested-collection state corruption), 2 high (callback refund misrouting, fee rounding), 13 fixed, 7 acknowledged. Storage accounting and admin/payout flows are the recurring themes."
---

# Potlock audit, Guvenkaya, January 2024

**Scope:** `PotLock/core` - the donation, pot, pot factory, registry, and sybil
smart contracts on NEAR. 4273 lines of code at baseline commit
`71f35051f81c333c85fafc42d073173191ad14ca`. Review period Jan 4-19, 2024;
final report Jan 30, 2024. 20 findings: 2 critical, 2 high, 1 medium, 9 low,
6 informational; 13 fixed, 7 acknowledged at report time.

## Findings

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| 1 | Critical | DoS of Process Payouts | Fixed |
| 2 | Critical | State Corruption On Setting Payout | Fixed |
| 3 | High | User Funds Not Returned On Error From Sybil Provider | Fixed |
| 4 | High | Arithmetic Issues In Fee Calculation | Fixed |
| 5 | Medium | No Runtime Overflow Checks Applied | Fixed |
| 6 | Low | Race Condition in Admin Process Payment | Fixed |
| 7 | Low | Max Project Check Is Invalid | Fixed |
| 8 | Low | Deactivating Provider Does Not Remove It From Default Providers | Fixed |
| 9 | Low | Deactivated Provider Retains All Stamps | Acknowledged |
| 10 | Low | Invalid Implementation Of New Admin Addition | Fixed |
| 11 | Low | Error-Prone Function Should Be Removed | Acknowledged |
| 12 | Low | Missing Limits On View Functions | Fixed (partial) |
| 13 | Low | Privileged Functions Are Not Protected By 2FA | Fixed |
| 14 | Low | Privileged Users Should Not Be Allowed To Have Other Roles | Fixed (partial) |
| 15 | Informational | Redundant Functionality | Acknowledged |
| 16 | Informational | Size Of The Contract Can Be Decreased | Fixed |
| 17 | Informational | Redundant State Statuses | Acknowledged |
| 18 | Informational | Usage of assert instead of require | Acknowledged |
| 19 | Informational | Using suboptimal panic function | Acknowledged |
| 20 | Informational | Redundant state check in initializers | Acknowledged |

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

## Source

Summarized from the public Guvenkaya report:
<https://github.com/Guvenkaya/public-reports/blob/master/Potlock-NEAR-Rust-Smart-Contract-Security-Assessment.pdf>.
Mirror used for retrieval (the as-delivered 61-page edition):
<https://github.com/NEARBuilders/audits/blob/main/Audits/Potlock-NEAR-Rust-Smart-Contract-Security-Assessment-Guvenkaya-Jan-30-2024.pdf>.
See the report for full detail and code excerpts.
