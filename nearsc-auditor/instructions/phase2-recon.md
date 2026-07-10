---
name: nearsc-auditor-recon
version: "1.1"
author: Vini B (@vinibarbosabr)
description: instructions for the nearsc-auditor Phase 2 - Recon. use it together with the orchestrator skill to map and understand the project and its source code for a NEAR smart contract audit in security research and bug bounty hunting activities.
activation:
  - phase 2 near audit
  - recon near contract
  - map source code
  - understand project
tags:
  - near
  - audit
  - security
---
# PHASE 2 - RECON | NEAR SC Auditor

**Description:** This is the second phase (Phase 2 - Recon) of a NEAR smart contract audit. Use it together with the nearsc-auditor orchestrator skill `nearsc-auditor/SKILL.md` to map and understand the project and source code we are auditing for security research and bug bounty hunting activities.

This phase should only start after "Phase 1 - Setup" has been completed.

## Execution Steps (nearsc-auditor-recon)

Detailed step-by-step execution that must be followed:

### Step 1 - Premises, Methodology, Basic Concepts, and References

Read the SKILL.md file (orchestrator skill) again to understand and internalize our premises, methodology, basic concepts, and references.

### Step 2 - Confirm "Phase 1 - Setup" Completion

Check the session's chat to confirm "Phase 1 - Setup" has been completed. If not, activate "Phase 1 - Setup, Step 4 - Document Executive Summary" or ask the user if they want to restart Phase 1.

Else, move to "Phase 2 - Recon" Step 3 below.

### Step 3 - Understand the Project

Read the project's README.md file, the first commented lines of the core file (usually `lib.rs` or `core.rs` or `main.rs`), and the project's published documentation when linked in the target repository (usually https://docs.'project-domain').

Answer these two questions based on your now-achieved understanding:

**A. What is this contract supposed to do?**
<!-- contract type (DEX/lending/DAO/oracle), what are the main actors involved (who calls the functions), and a brief summary on what it is supposed to do -->

**B. What is this contract NOT supposed to do?**
<!-- potential exploits that could be performed against this type of contract, setting the baseline for some potential hypotheses (do NOT limit your scope to these first hypotheses in the following phases, this is just an initial baseline, we need to remain open to all the future findings) -->

### Step 4 - Map the Source Code

We will now understand the repository's structure, how the folders, important files, and the core contract's logic has been engineered.
#### Task 1 - Get User's Input
Provide the following code block for the user to copy and paste manually, then request the user to share the command output in the chat.

```Bash
cd ~/vinib-audits/nearsc/audit-<project-name>/code/
cloc .
ls --tree
rg '#\[near\]|#\[near_bindgen\]' --type rust -A 3
rg 'pub fn ' --type rust
```

#### Task 2 - Analyze and Map
After receiving the input from Task 1, process and analyze all the information to start building a usable map for the audit.

1. print cloc's summary for `*.rs` files only.
2. print a simplified version of the structure, focusing on the contract's src folder and comment the most important files we should give more attention to during Phase 3 (HUNT). Set a HIGH/MEDIUM/LOW priority and give a brief one-liner explanation on what each does.
3. make a quick summary of the core public functions (from the most important files) we should be aware of, as they are the contract's endpoints and usually the main attack surfaces , considering (usually) anyone can call them with onchain transactions.

Then, ask the user if the wants to expand on that with a full detailed analysis based on this initial mapping. If so:

1. list the most important functions and provide a one-liner explanation on what each of them does.
2. i won't set any minimum or maximum functions, as you need to be able to effectively filter out the noise, while including all functions that matter.
3. add any worthy notable observations to guide us in the next phase.
4. finish with a summary recommendation for Phase 3 - Hunt.

#### Output Example:

--- START: recon-notes-map.md ---
==PHASE 2, STEP 4, TASK 2 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Recon Notes Map**
**Project:** 'project-name'
**Version:** 1.0 

**From `cloc .` (Rust files only):**
- Total Rust files: 'X' | Code LOC: '~Y'

**Simplified Project Structure + Commented Priority**

```bash
'core-contract-dir'/
├── lib.rs                  # HIGH - Main contract struct + initialization
├── 'main-business-logic.rs' # CRITICAL - Core user flows
├── 'async-interaction.rs'   # CRITICAL - Cross-contract / callback logic
├── 'admin.rs'               # HIGH - Owner, managers, pause
├── upgrade.rs               # MEDIUM - Upgrade + migration
└── (view, internal, events, types...) # MEDIUM/LOW
```

**TABLE 1: Priority Files**

|Priority|File|Reason|
|---|---|---|
|Critical|'main-business-logic.rs'|Primary user entrypoints|
|Critical|'async-interaction.rs'|Callbacks and cross-contract calls|
|High|'admin.rs'|Access control and privileged functions|
|High|upgrade.rs|Upgrade path and state migration|
|High|lib.rs|Contract initialization|

**TABLE 2: Core Public Functions (Main Attack Surface)

|Function|File|Type|One-line Purpose|
|---|---|---|---|
|'function_name_1'|'main-business-logic.rs'|Payable|Core user action|
|'function_name_2'|'main-business-logic.rs'|-|State-changing operation|
|'admin_function'|'admin.rs'|Owner|Privileged operation|
|upgrade / migrate|upgrade.rs|Owner|Contract upgrade|
**Notable Observations**
- Main business logic concentrated in 'X' files.
- Heavy use of async promises/callbacks (review callback protection).
- Access control via owner/manager pattern.
- Upgrade mechanism present.

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: recon-notes-map.md --

---

**IMPORTANT** The example template above is just that: an example. You need to adapt your mapping for structure, files, and core public functions according to each project and their respective particularities.
### Step 5 - Attack Surface Map and Checklist Draft

Ask the user for confirmation to create a more detailed attack surface map and a checklist for these specific files and first recon notes.

1. Create a table with the high-risk areas (ranked by priority): Rank, Area, Files Involved, Risk Level, Main Concern.
2. Create a detailed HUNT Checklist for each file that will help us in the next Phase (3). It will serve as a brief draft that must be improved later (we will dive deeper into each item individually).
	1. Start with the file name,
	2. follow with a 3-word explainer, and
	3. add a priority rank/severity classification.
	4. Then, list focus areas and the security checklist
3. Create a table with general things to watch for across all files, with: Category, What to Look For, Severity.

#### Example Output

--- START: recon-notes-check.md ---
==PHASE 2, STEP 5, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Recon Notes Checklist**

**High-Risk Areas (Ranked)**

| Rank | Area                        | Files Involved                  | Risk     | Main Concern                     |
|------|-----------------------------|---------------------------------|----------|----------------------------------|
| 1    | Async / Callback Logic      | 'async-interaction.rs'          | Critical | Callback protection & ordering   |
| 2    | Core Business Logic         | 'main-business-logic.rs'        | Critical | User fund / state manipulation   |
| 3    | Access Control              | 'admin.rs', lib.rs              | High     | Privilege escalation             |
| 4    | Upgrade & Migration         | upgrade.rs                      | High     | Storage layout changes           |
| 5    | Token / Accounting Logic    | 'token-module'                  | High     | Standard compliance + math       |

**Concise HUNT Checklist (Pre-Phase 3)**

**A. `'main-business-logic.rs'` – Core Logic** (Critical)
- Focus: Main payable and state-changing functions
- [ ] Input validation on all public functions
- [ ] Pause mechanism enforcement
- [ ] Reentrancy / async re-entry risks
- [ ] Accounting / balance correctness

**B. `'async-interaction.rs'` – Callbacks** (Critical)
- Focus: All callback functions
- [ ] Proper `#[private]` or `assert_private()` protection
- [ ] Direct callback invocation risk
- [ ] Result handling and error cases
- [ ] Gas usage in promise chains

**C. `'admin.rs'` – Admin Functions** (High)
- [ ] All privileged functions have proper authorization checks
- [ ] Pause bypass possibilities
- [ ] Owner/manager role separation

**D. `upgrade.rs` + `lib.rs`** (High)
- [ ] `migrate()` correctly handles storage changes
- [ ] Re-initialization protection after deployment

**General Things to Watch Across All Files**

| Category         | What to Look For                                   | Severity |
|------------------|----------------------------------------------------|----------|
| Access Control   | Missing/weak `assert_owner`, `assert_private`      | High     |
| Callbacks        | Unprotected or incorrectly protected callbacks     | Critical |
| Accounting       | Balance / share mismatches                         | High     |
| Pause            | Critical functions callable while paused           | High     |
| Async Patterns   | Re-entry via promise/callback chains               | High     |
| Upgrade Safety   | Storage migration and state compatibility          | High     |
**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: recon-notes-check.md ---

---

**IMPORTANT** The example template above is just that: an example. You need to adapt your mapping for structure, files, and core public functions according to each project and their respective particularities.

### Step 6 - Known Attack Surfaces and Hypothesis List

Generate a vulnerability hypothesis list with common attack patterns for this type of contract.

Create one table for each severity risk (CRITICAL/HIGH/MEDIUM/LOW), with # (list id), hypothesis, description, why it's relevant, key files to check, likelihood.

Finish with a recommended focus order for phase 3.

#### Example Output

--- START: recon-notes-atk.md ---
==PHASE 2, STEP 6, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Recon Notes Attack Vectors**

**Vulnerability Hypotheses**

**Critical**

| #   | Hypothesis   | Why Relevant (NEAR) | Key Files | Likelihood |
| --- | ------------ | ------------------- | --------- | ---------- |
| 1   | Hypothesis 1 | ...                 | 'file.rs' | High       |
| 2   | Hypothesis 2 | ...                 | ...       | Medium     |
| 3   | Hypothesis 1 | ...                 | ...       | Low        |

**High**

| # | Hypothesis                     | Why Relevant (NEAR)                  | Key Files             | Likelihood |
|---|--------------------------------|--------------------------------------|-----------------------|------------|
| 4 | Pause Bypass                   | Critical functions ignore pause      | 'admin.rs' + logic    | Medium     |
| 5 | Broken Migration               | Storage layout changes break state   | upgrade.rs            | High       |
| 6 | Async Reentrancy               | Re-entry through promise chains      | Multiple              | Medium     |

**Key Attack Patterns (NEAR Contracts)**

| Attack Pattern   | Description   | Relevant Files | Severity |
| ---------------- | ------------- | -------------- | -------- |
| Attack Pattern 1 | Description 1 | 'file1.rs'     | Critical |
| Attack Pattern 2 | Description 2 | 'file2.rs'     | High     |
| Attack Pattern 3 | Description 3 | 'file3.rs'     | Medium   |
| Attack Pattern 4 | Description 4 | 'file4.rs'     | Low      |

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: recon-notes-atk.md ---

### Step 7 - Confirm "Phase 2- Recon" Completion

Confirm "Phase 2 - Recon" has been completed and ask the user if they want to start "Phase 3 - Hunt" according to the `instructions/phase3-hunt.md` skill.

## Changelog

- 2026-06-22: Create file
- 2026-06-23: Improve templates on "example outputs" to be more general and prevent AI bias to certain patterns

---

File created on 2026-06-22