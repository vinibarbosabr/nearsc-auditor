---
title: "LiNEAR audit, Hacken, May 2024"
kind: audit
project: linear-protocol
year: 2024
source: "https://github.com/linear-protocol/audits/blob/main/Hacken%20-%20Smart%20Contract%20Code%20Review%20and%20Security%20Analysis%20Report%20for%20LiNEAR%20-%20202405.pdf"
retrieved: 2026-11-09
confidence: verified-public
severity_counts: {"critical":0,"high":0,"medium":1,"low":1,"info":1}
tags: [liquid-staking, storage-griefing, events, nep-145]
summary: "Hacken's 2024 LiNEAR review: storage griefing on deposit-account creation (Medium), inability to free unused storage (Low), and missing events on privileged setters (Info)."
---

# LiNEAR audit, Hacken, May 2024

**Scope:** `linear-protocol/LiNEAR`, liquid staking contract. Public report
dated Apr 30, 2024.

## Findings

### F-2024-1979, Medium: storage griefing via deposit-account creation

The `deposit` function creates a new `Account` struct in storage without
charging the user for it. Measured cost: ~0.004 NEAR of contract-paid storage
per account versus ~0.0005 NEAR of user-paid gas. Zero-amount deposits were
allowed, so an attacker could lock contract funds by creating many empty
accounts. Remediation adopted: disallow zero-amount deposits.

### F-2024-1983, Low: cannot free storage for unused accounts

No path to delete unused accounts and reclaim storage. The team decided not to
add storage withdrawal or unregistering because of the exploit surface
highlighted by F-2024-1979.

### F-2024-1975, Info: missing events on critical state changes

`set_owner`, `add_manager`, `remove_manager`, `set_beneficiary`,
`remove_beneficiary`, `set_treasury`, `set_whitelist_contract_id`, `pause`,
and `resume` emit no events, so off-chain monitoring cannot detect changes.

## Why it matters for nearsc

- Direct real-world evidence for NS008 (storage griefing) with measured costs,
  and for NS012 (privileged setters): the same method set also lacked events.
- The team's fix (block zero-amount deposits) is a cheap mitigation, not a full
  NEP-145 implementation; nearsc reports the pattern and leaves the remedy to
  the maintainer.

## Source

Summarized from the public Hacken report:
<https://github.com/linear-protocol/audits/blob/main/Hacken%20-%20Smart%20Contract%20Code%20Review%20and%20Security%20Analysis%20Report%20for%20LiNEAR%20-%20202405.pdf>.
