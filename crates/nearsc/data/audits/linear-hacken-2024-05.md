---
title: "LiNEAR audit, Hacken, May 2024"
kind: audit
project: linear-protocol
year: 2024
source: "https://github.com/linear-protocol/audits/blob/main/Hacken%20-%20Smart%20Contract%20Code%20Review%20and%20Security%20Analysis%20Report%20for%20LiNEAR%20-%20202405.pdf"
retrieved: 2026-11-09
confidence: verified-public
severity_counts: {"critical":0,"high":0,"medium":1,"low":1,"info":1}
tags: [liquid-staking, storage-griefing, privileged-setter-unguarded, unbounded-iteration, events, nep-145]
summary: "Hacken's 2024 LiNEAR review: storage griefing on deposit-account creation (Medium), inability to free unused storage (Low), and missing events on privileged setters (Info). Findings classified per D-017."
---

# LiNEAR audit, Hacken, May 2024

**Scope:** `linear-protocol/LiNEAR` (MIT), liquid staking contract. Public
report dated Apr 30, 2024.

## Findings

| ID | Severity | Finding | Status | Vector |
| --- | --- | --- | --- | --- |
| F-2024-1979 | Medium | Storage griefing via deposit-account creation: `deposit` creates a new `Account` struct without charging the user (~0.004 NEAR contract-paid storage per account vs ~0.0005 NEAR user-paid gas); zero-amount deposits allowed, so an attacker could lock contract funds with empty accounts | Remediation adopted (disallow zero-amount deposits) | `storage-griefing` (NS008) |
| F-2024-1983 | Low | Cannot free storage for unused accounts: no path to delete unused accounts and reclaim storage; team chose not to add storage withdrawal/unregistering because of the exploit surface in F-2024-1979 | Not fixed (design decision) | `uncategorized` (storage lifecycle; no pattern file yet) |
| F-2024-1975 | Info | Missing events on critical state changes: `set_owner`, `add_manager`, `remove_manager`, `set_beneficiary`, `remove_beneficiary`, `set_treasury`, `set_whitelist_contract_id`, `pause`, `resume` emit no events | Not fixed (per report) | `uncategorized` (observability; recurring ecosystem hygiene theme) |

## Why it matters for nearsc

- F-2024-1979 is direct real-world evidence for NS008 (storage griefing) with
  measured costs.
- F-2024-1975's method set is NS012 territory (privileged setters): the same
  methods also lacked events, and unguarded setters are the scanner-detectable
  half of that pair.
- The team's fix (block zero-amount deposits) is a cheap mitigation, not a
  full NEP-145 implementation; nearsc reports the pattern and leaves the
  remedy to the maintainer.

## Source

Summarized from the public Hacken report:
<https://github.com/linear-protocol/audits/blob/main/Hacken%20-%20Smart%20Contract%20Code%20Review%20and%20Security%20Analysis%20Report%20for%20LiNEAR%20-%20202405.pdf>.
This entry is summary-depth (D-017): findings classified, no per-finding
blocks; upgrade to blocks is v0.2 polish.
