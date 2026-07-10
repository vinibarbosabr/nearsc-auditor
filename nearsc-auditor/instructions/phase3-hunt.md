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

Read the NEAR smart contract security checklist in the file `resources/near-docs/checklist.md`.

Make a checklist adapted for this target, organized by categories and items.

Then, make a list for each checklist item with a respective suggested ripgrep (`rg`) command for the user to later execute and verify your audit. The command is optimized for this target and should include key words and sentence patterns, depth, files, and other specifications that will help with the checking.

Audit the target's code base carefully, having this security checklist in mind. Looks for checklist misses. Functions, types, and execution paths that have missed these items is what we are hunting for in this step. This is where the low-hanging fruits will be.

Share your findings in detail with the user

#### Output
1. **Checklist** organized by category and item,
2. **Command List** for each item with its respective `rg` command to be executed by the user,
3. **Table 1: Checklist Findings**, ranked by severity, your checklist-based findings, affected elements (functions, types, etc), affected files, and impact hypothesis
4. **Recommendations** any recommendation you may have for hunting more checklist-based vulnerabilities for this project in particular

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
| CRITCIAL/HIGH/MEDIUM/LOW | 'Title: Finding 1' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| CRITCIAL/HIGH/MEDIUM/LOW | 'Title: Finding 2' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| ...                      | ...                | ...                                         | ...                                         | ...                                   |     |

**Recommendations**
<!-- 2-3 paragraph recommendations for hunting more checklist-based vulnerabilities for this project in particular -->

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: hunt-notes-check.md --

### Step 4 - Hunt for Security Patterns

Moving forward, we will dive into security patterns independently or (when possible) delegate unique agents (or sub-agents) for specific hunting work at each pattern for more efficient token usage and context management.

Agents must read the respective resource material for each security pattern and do the proper, careful verification against keywords and code patterns through the entire project's code base and contracts' source code.

Organize and plan this hunt according to known attack vectors and patterns based on `resources/near-docs` files (per pattern, listed below), PLUS public findings we studied on Phase 2, documented at `recon-notes-find.md`. Give special attention to findings that weren't fully fixed (mitigated, accepted, ignored, etc) and for recent changes that might have reverted previous fixes.







Output a focused checklist for each pattern, thought for this project in particular, and set priority checks (high, medium, low priority) with suggested key words, patterns, or any other specifics that are relevant for the contract we are currently auditing. You can use the user's findings from Phase 2 but do not limit yourself by them.

**IMPORTANT:** The user can make mistakes and/or miss things.

### Step 5 - 


## Changelog

- 2026-06-22: Create file
- 2026-07-10: Build instructions until Step 4 (incomplete)

---

File created on 2026-06-22