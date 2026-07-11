---
name: nearsc-auditor-hunt
version: "1.1"
author: Vini B (@vinibarbosabr)
description: instructions for the nearsc-auditor Phase 3- Hunt. use it together with the orchestrator skill to hunt for vulnerabilities and checklist patterns in its source code for a NEAR smart contract audit in security research and bug bounty hunting activities.
activation:
  - phase 3 near audit
  - hunt near contract
  - hunt vulnerabilities
  - near security checklist
  - smart contract checklist
tags:
  - near
  - audit
  - security
  - checklist
---
# PHASE 3 - HUNT | NEAR SC Auditor

**Description:** This is the third phase (Phase 3 - Hunt) of a NEAR smart contract audit. Use it together with the nearsc-auditor orchestrator skill `nearsc-auditor/SKILL.md` to hunt for vulnerabilities and go through a checklist and known patterns in its source code for a NEAR smart contract audit in security research and bug bounty hunting activities.

This phase should only start after "Phase 2 - Recon" has been completed.

Every suggested `rg` must be immediately runnable, include file filters when possible, and target both definition and usage sites.

## Execution Steps (nearsc-auditor-hunt)

Detailed step-by-step execution that must be followed:

### Step 1 - Premises, Methodology, Basic Concepts, and References

Read the SKILL.md file (orchestrator skill) again to understand and internalize our premises, methodology, basic concepts, and references.

### Step 2 - Confirm "Phase 2 - Recon" Completion

Check the session's chat to confirm "Phase 2 - Recon" has been completed. If not, identify in what Step we stopped and activate this Phase 2 step again or ask the user if they want to restart Phase 2 and at which step.

Else, move to "Phase 3 - Hunt" Step 3 below.

You **should have NOT created any strong biases yet!**
We were just doing recognition. The real hunt starts now.

### Step 3 - Hunt for Security Checklist

Read the NEAR smart contract security checklist in the file `resources/near-docs/security-checklist.md`.

Make a checklist adapted for this target, organized by categories and items.

Then, make a list for each checklist item with a respective suggested ripgrep (`rg`) command for the user to later execute and verify your audit. The command is optimized for this target and should include key words and sentence patterns, depth, files, and other specifications that will help with the checking.

Audit the target's code base carefully, having this security checklist in mind. Looks for checklist misses. Functions, types, and execution paths that have missed these items is what we are hunting for in this step. This is where the low-hanging fruits will be.

Share your findings in detail with the user

#### Output
1. **Checklist** organized by category and item,
2. **Command List** for each item with its respective `rg` command to be executed by the user,
3. **Table 1: Checklist Findings**, ranked by severity, your checklist-based findings, affected elements (functions, types, etc), affected files, and impact hypothesis
4. **Recommendations** any recommendation you may have for hunting more checklist-based vulnerabilities for this project in particular
5. **List**, of recommended prioritization for Phase 3, Step 4.

#### Output Example
--- START: hunt-notes-check.md ---
==PHASE 3, STEP 3, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Hunt Notes Checklist**
**Project:** 'project-name'
**Version:** 1.0 

**Checklist**
1. [ ] All Private Methods Are Decorated as `private`
2. [ ] `predecessor` and `signer` Are Used Correctly
3. [ ] State Growth Has Sufficient Balance Coverage
4. [ ] All Collections Have Unique IDs
5. [ ] Check for Underflow and Overflow
6. [ ] Leave Enough Balance for Storage Costs
7. [ ] Deduct User Funds Before Sending
8. [ ] All Private Callbacks Are Marked as `private`
9. [ ] All Cross-Contract Calls Have Callbacks
10. [ ] Callbacks Check for Errors and Roll Back State
11. [ ] Callbacks Return Money to Predecessor If Necessary
12. [ ] Callbacks Are Free of `panic!`
13. [ ] Callbacks Have Sufficient GAS
14. [ ] Contract Not Left in Exploitable State Between Call and Callback

**Command List for manual verification**
1. All Private Methods Are Decorated as `private`
```Bash
rg # suggested ripgrep commmand syntax with keywords and other specifications
```

2. `predecessor` and `signer` Are Used Correctly
```Bash
rg # suggested ripgrep commmand syntax with keywords and other specifications
```

3. ...

**TABLE 1: Checklist Findings**

<!-- 2-4 paragraph summary of your findings and relevant observations -->

| Severity                 | Finding            | Affected Elements                           | Affected Files                              | Impact                                |     |
| ------------------------ | ------------------ | ------------------------------------------- | ------------------------------------------- | ------------------------------------- | --- |
| CRITICAL/HIGH/MEDIUM/LOW | 'Title: Finding 1' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| CRITICAL/HIGH/MEDIUM/LOW | 'Title: Finding 2' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| ...                      | ...                | ...                                         | ...                                         | ...                                   |     |

**Recommendations**
<!-- 2-3 paragraph recommendations for hunting more checklist-based vulnerabilities for this project in particular -->

**Ready for Phase 3 Step 4 – Pattern Hunt!**

Recommended order of attack pattern hunting for this target (based on recon-notes-map + recon-notes-exec + public findings):

1. HIGH: 'High-Priority Pattern 1' (`security-'pattern'.md`)
2. HIGH: 'High-Priority Pattern 2' (`security-'pattern'.md`)
3. MEDIUM: 'Medium-Priority Pattern' (`security-'pattern'.md`)
4. MEDIUM: 'Medium-Priority Pattern' (`security-'pattern'.md`)
5. LOW: 'Low-Priority Pattern' (`security-'pattern'.md`)
6. Dynamic: Non-fixed public findings + recent reverts

**Reply with:**
- "start 1" (or "start 'pattern-name'")
- "batch 1-3"
- "skip X"
- or "custom: pattern1, pattern2"


**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: hunt-notes-check.md --

### Step 4 - Hunt for Security Patterns

Moving forward, we will dive into security patterns independently or (when possible) delegate unique agents (or sub-agents) for specific hunting work at each pattern for more efficient token usage and context management.

Agents must read the respective resource material for each security pattern and do the proper, careful verification against keywords and code patterns through the entire project's code base and contracts' source code.

Organize and plan this hunt according to known attack vectors and patterns based on `resources/near-docs/<atk-pattern.md>` files (per pattern, listed below), PLUS public findings we studied on Phase 2, documented at `recon-notes-find.md`. Give special attention to findings that weren't fully fixed (mitigated, accepted, ignored, etc) and for recent changes that might have reverted previous fixes.

Generate a focused checklist for each pattern, thought for this project in particular, and set priority checks (high, medium, low priority) with suggested key words, patterns, or any other specifics that are relevant for the contract we are currently auditing.

Each attack pattern will initiate its own TASK following user's confirmation. When you end a task (pattern), output accordingly and ask the user confirmation before starting the next TASK.
#### Attack Patterns (TASKS)
- Storage Cost Attacks → `security-storage.md`
- Cross-Contract Calls → `security-callbacks.md`
- Ensure it is the User (1yⓃ) → `security-one_yocto.md`
- Sybil Attacks → `security-sybil.md`
- Front Running → `security-frontrunning.md`
- Reentrancy Attacks → `security-reentrancy.md`
- Random Numbers → `security-random.md`
- 'Non-Fixed Public Finding 1' → `recon-notes-find.md`
- 'Non-Fixed Public Finding 2' → `recon-notes-find.md`
- 'Reverted Fix Bug 1' → `recon-notes-find.md`
- etc...

The task completion will require a pattern-focused audit and vulnerability hunt against the target, a table with your findings, a checklist with suggested commands for manual verification (by the user), and notable observations for Phase 4 - Attack.

You will repeat this same methodology for each task (pattern).

#### Output

Say you are ready to start the next TASK and ask for user confirmation, mentioning the TASK number, attack vector, and resource needed. Wait for the user to confirm and upload the requested file.

While doing each TASK:

1. **Initiate** TASK X,
2. **Findings**, a 2-4 paragraph summary describing your findings.
3. **TABLE 1: Findings**, ranked by severity, the finding, affected elements (functions, types, macros, etc), affected files, impact hypothesis,
4. **Checklist**, with suggested ripgrep commands for user-driven, manual verification locally
5. **Notable observations** and recommendations for the Attack phase (Phase 4)

#### Output Example

--- START: hunt-notes-patt-1.md ---
==PHASE 3, STEP 4, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Hunt Notes Patterns**
**Project:** 'project-name'
**Version:** 1.0 

**Initiating** 'TASK 1' hunting for 'Storage Cost Attack' patterns.

**Resources**: '`security-storage.md`'

**TABLE 1: Pattern Findings**

<!-- 2-4 paragraph summary of your findings and relevant observations -->

| Severity                 | Finding            | Affected Elements                           | Affected Files                              | Impact                                |     |
| ------------------------ | ------------------ | ------------------------------------------- | ------------------------------------------- | ------------------------------------- | --- |
| CRITICAL/HIGH/MEDIUM/LOW | 'Title: Finding 1' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| CRITICAL/HIGH/MEDIUM/LOW | 'Title: Finding 2' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| ...                      | ...                | ...                                         | ...                                         | ...                                   |     |


**Checklist**
1. [ ] 'Checklist Item 1'
2. [ ] 'Checklist Item 2'
3. [ ] ...

**Command List for manual verification**
1. 'Checklist Item 1'
```Bash
rg # suggested ripgrep commmand syntax with keywords and other specifications
```

2. 'Checklist Item 2'
```Bash
rg # suggested ripgrep commmand syntax with keywords and other specifications
```

3. ...


**Notable Observations**
<!-- 2-3 paragraph with notable observations and recommendations for hunting more checklist-based vulnerabilities for this project in particular -->

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: hunt-notes-patt-1.md --

### Step 5 - Hunt Findings Accumulator

Create a `hunt-findings.md` accumulator that will list, organize, and index all findings discovered so far with one-liners for easier reference and searching.

#### Output

Output a master table organizing the findings following the examples from previous steps.

#### Output Example

--- START: hunt-findings.md ---
==PHASE 3, STEP 5, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Hunt Findings Accumulator
**Project:** 'project-name'
**Version:** 1.0 


**MASTER TABLE: Findings**

| Severity                 | Finding            | Affected Elements                           | Affected Files                              | Impact                                |     |
| ------------------------ | ------------------ | ------------------------------------------- | ------------------------------------------- | ------------------------------------- | --- |
| CRITICAL/HIGH/MEDIUM/LOW | 'Title: Finding 1' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| CRITICAL/HIGH/MEDIUM/LOW | 'Title: Finding 2' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| ...                      | ...                | ...                                         | ...                                         | ...                                   |     |


**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: hunt-findings.md --

### Step 6 - Confirm "Phase 3- Hunt" Completion

Confirm "Phase 3 - Hunt" has been completed and ask the user if they want to start "Phase 4 - Attack" according to the `instructions/phase4-attack.md` skill. Ask the user to upload this file.

## Changelog

- 2026-06-22: Create file
- 2026-07-10: Build instructions (completed)
- 2026-07-11: Improve steps with better instructions

---

File created on 2026-06-22