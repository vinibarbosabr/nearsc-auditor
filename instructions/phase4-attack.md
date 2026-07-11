---
name: nearsc-auditor-attack
version: "1.0"
author: Vini B (@vinibarbosabr)
description: instructions for the nearsc-auditor Phase 3 - Attack. use it together with the orchestrator skill to find and validate vulnerabilities in a targetted NEAR smart contract audit for ethical security research and bug bounty hunting activities.
activation:
  - phase 4 near audit
  - attack near contract
  - attack vulnerabilities
  - exploit target
  - proof of concept
  - bug poc
  - exploit poc
  - attack poc
  - vulnerability poc
tags:
  - near
  - audit
  - security
---
# PHASE 4 - ATTACK | NEAR SC Auditor

**Description:** This is the fourth phase (Phase 4 - Attack) of a NEAR smart contract audit. Use it together with the nearsc-auditor orchestrator skill `nearsc-auditor/SKILL.md` to find and validate vulnerabilities in a targetted NEAR smart contract audit for ethical security research and bug bounty hunting activities.

This phase should only start after "Phase 3 - Hunt" has been completed.

**IMPORTANT:** Activate a full red team "attacker mindset" in this phase. We want to find **real** and **demonstrable** exploitable vulnerabilities, leveraging all our work so far (in previous phases). Focus on tangible results.

## Execution Steps (nearsc-auditor-attack)

Detailed step-by-step execution that must be followed:

### Step 1 - Premises, Methodology, Basic Concepts, and References

Read the SKILL.md file (orchestrator skill) again to understand and internalize our premises, methodology, basic concepts, and references.

### Step 2 - Confirm "Phase 2 - Recon" Completion

Check the session's chat to confirm "Phase 3 - Hunt" has been completed. If not, identify in what Step we stopped and activate this Phase 3 step again or ask the user if they want to restart Phase 3 and at which step.

Else, move to "Phase 4 - Attack" Step 3 below.

### Step 3 - Attack Surface Map

Read all the notes we have so far:

- `REPORT.md`
- `recon-notes-map.md`
- `recon-notes-exec.md`
- `recon-notes-find.md`
- `hunt-notes-check.md`
- `hunt-notes-patt-1.md`
- `hunt-notes-patt-2.md`
- `hunt-notes-patt-<...>.md`
- `hunt-notes-zero.md`

Organize and build a detailed attack surface map with all relevant findings ranked by SEVERITY and impact based on the program's rules and scope. You can remove obvious duplicates, but be careful to not remove false-duplicates (similar, but still different).

Request the user to provide the .md file for the severity classification. Prioritize the use of the documentation from the platform hosting the bounty program for that and use the CVSS 4.0 in the lack of a good customized method.

For the PoC, we will favor using NEAR workspaces: [workspaces-rs](https://github.com/near/near-workspaces-rs) or [workspaces-js](https://github.com/near/near-workspaces-js). Rust is preferred, unless the target repo has a solid foundation for JavaScript or other environment. Check the target's tests directory and cargo for insights.

In this first moment (Step 3), we won't write the PoC file. Just set the method that we will use to build it later in following steps.

#### Output
The output should include:

1. **Attack Surface**, a 2-4 paragraph summary describing the attack surface against this target.
2. **Findings**, an initial report with one detailed item per findings, ranked by severity. Include: the finding, brief description of the attack, affected elements (functions, types, macros, etc), affected files, impact hypothesis, exploit likelihood, and a brief list with recommendations of steps to build the PoC

#### Output Example

--- START: attack-notes-map.md ---
==PHASE 4, STEP 3, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Attack Notes Mapping the Atk Surface**
**Project:** 'project-name'
**Version:** 1.0 

**Attack Surface**
<!-- 2-4 paragraph summary describing the attack surface against this target -->

**Findings**

**I. 'Title for Finding 1'**

**Severity:** CRITICAL/HIGH/MEDIUM/LOW
**Affected Elements:** `'affected_function'`, `'affected_type'`, `'affected_macro'`
**Affected Files:** 'affected-file-1.rs', 'affected-file-2.rs'

**Attack Surface Description**
<!-- 1-2 paragraph summary describing the attack surface of this finding -->

**Impact and Likelihood:**
<!-- 1 paragraphs with impact and likelihood assessment -->

**Building the PoC for sandboxed/local tests:**
1. Step 1
2. Step 2
3. Step 3
4. Step 4
5. Step 5

**II. 'Title for Findind 2'

**Severity:** CRITICAL/HIGH/MEDIUM/LOW
**Affected Elements:** `'affected_function'`, `'affected_type'`, `'affected_macro'`
**Affected Files:** 'affected-file-1.rs', 'affected-file-2.rs'

**Attack Surface Description**
<!-- 1-2 paragraph summary describing the attack surface of this finding -->

**Impact and Likelihood:**
<!-- 1 paragraphs with impact and likelihood assessment -->

**Building the PoC for sandboxed/local tests:**
1. Step 1
2. Step 2
3. Step 3
4. Step 4
5. Step 5

**III. (...)**

(...)

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: attack-notes-map.md --

### Step 4 - Attacking! (the PoC)

**IMPORTANT:** Remember we are whitehats. We are not literally attacking the target. We are researching for vulnerabilities so we can help this project to increase its security, while also being rewarded for that via bounties.

Now, together with the user, validate each attack surface finding individually and exploit each of them in a controlled environment (workspaces, sandboxes, local tests, etc). We will only exploit (use) an onchain forked, deployed contract on testnet when proving the concept locally isn't possible.

Each finding and PoC must be treated as a separate TASK (TASK 1, TASK 2, TASK 3, etc.).

Ask the user which Finding they want to attack first. At this point, the user is supposed to have manually validated the attack hypothesis, with in-depth code reading and thinking about the exploit theory alone.

#### Output

The output here is literally the proof of concept (PoC) file that will later be provided to the target/client for reproduction.

Study all the tests built for this smart contract (the user can provide files found in the target repository) and the `workspaces-rs-README.md` file the user should've already provided (request it, if you can't find this file).

Reproduce the details for the attack surface we are currently working on, then output a clean, ready to copy and paste test file inside a code block, together with our usual header and footer for out markdown notes—same as in previous steps and phases.

Notes file name should start with "poc-" followed by the reduced attack surface title: `poc-<reduced-attack-surface-title>.md`. The test file name (the poc) is the same, but ending in `.rs` or the correct extension for the test type (`.js`, `.ava`, etc).

#### Output Example

--- START: poc-'reduced-attack-surface-title'.md ---
==PHASE 4, STEP 4, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – PoC: Reduced Attack Surface Title**
**Project:** 'project-name'
**Version:** 1.0 

**'Attack Surface Finding Title'**

**Severity:** CRITICAL/HIGH/MEDIUM/LOW
**Affected Elements:** `'affected_function'`, `'affected_type'`, `'affected_macro'`
**Affected Files:** 'affected-file-1.rs', 'affected-file-2.rs'

**Attack Surface Description**
<!-- 1-2 paragraph summary describing the attack surface of this finding -->

**Impact and Likelihood:**
<!-- 1 paragraphs with impact and likelihood assessment -->

**PoC:**

```Rust title:poc-<reduced-attack-surface-title>.rs
// PoC for sandboxed, local testing using the workspaces-rs framework
// inspired by other tests from our target's repository
```

**Reproduction Steps:**
<!-- 1-2 paragraph summary describing the reproduction steps -->

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: poc-'reduced-attack-surface-title'.md --

### Step 6 - Ask the User What's Next

The user will now guide you on the next steps.
Either refining/adjusting the current PoC we are working on, asking for help for testing it further, or moving to the next TASK (ie, the next attack surface finding).

The user may also ask for help to improve the final REPORT.md file or to submit the report for the bug bounty program.

Ask the user what they want and follow along.

## Changelog

- 2026-07-11: Create file

---

File created on 2026-07-11