---
name: nearsc-auditor-recon
version: "1.4"
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
rg 'near_sdk|near_contract_standards|#[payable]|#[private]|#[callback]|ext_contract|Promise' --type rust -n
cat Cargo.toml | head -80
```

#### Task 2 - Analyze and Map
After receiving the input from Task 1, process and analyze all the information to start building a usable map for the audit.

1. print cloc's summary for `*.rs` files only.
2. print a simplified version of the structure, focusing on the contract's src folder and comment the most important files we should give more attention to during Phase 3 (HUNT). Set a HIGH/MEDIUM/LOW priority and give a brief one-liner explanation on what each does.
3. make a quick summary of the core public functions (from the most important files) we should be aware of, as they are the contract's endpoints and usually the main attack surfaces , considering (usually) anyone can call them with onchain transactions.

Then, expand on that with a full detailed analysis based on this initial mapping. If so:

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

| Function          | File                     | Type    | One-line Purpose         |
| ----------------- | ------------------------ | ------- | ------------------------ |
| 'function_name_1' | 'main-business-logic.rs' | Payable | Core user action         |
| 'function_name_2' | 'main-business-logic.rs' | -       | State-changing operation |
| 'admin_function'  | 'admin.rs'               | Owner   | Privileged operation     |
| upgrade / migrate | upgrade.rs               | Owner   | Contract upgrade         |

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

### Step 5 - Map the Core Functions Execution

We will now improve our understanding of the core functions discovered above. Function execution path and internal dependencies are the keywords for this step.

For each core function listed, unless the user explicitly excludes something, we need to understand what happens when they are called:

1. What state they get from the contract or the NEAR blockchain,
2. What other functions they call during execution,
3. What guardrails they have to ensure a safe execution, as intended,
4. What are the actors who can call these functions,
5. What state they change at each call and protected by each guardrail.

Request the user for further context for the definition and/or reference of any functions you can't clearly understand the execution due to missing code files.

#### Output

Phase 2, Step 5's output must include:
1. **Summary** mentioning the execution logic of this contract's core functions, dependencies, types, and other relevant aspects with security research in mind.
2. **Table 1: Dependency Map**, with the core function name and its file, plus core internal dependencies (functions, types, macros, etc) present in their execution and the file in which their definition is set.
3. **Table 2: Execution Map**, with the execution path of each core function (what happens when it's called), step by step, in order.
4. **Risk Assessment**, an initial hypothesis and first risk assessment based on these maps. Include what the most critical and risky execution paths are, and the most likely places to find vulnerabilities and attack surfaces within the program's scope.
5. **List**, top 5 riskiest execution paths,
#### Output example

--- START: recon-notes-exec.md ---
==PHASE 2, STEP 5, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Recon Notes Execution**
**Project:** 'project-name'
**Version:** 1.0 

**Summary**
<!-- 2-5 paragraphs summary mentioning the execution logic of this contract's core functions, dependencies, types, and other relevant aspects with security research in mind. -->

**TABLE 1: Dependency Map**

| Function             | File                 | Dependencies                                                      | Files                                                                                    |
| -------------------- | -------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| 1. 'function_name_1' | 'function_1_file.rs' | 1.1. 'dependency_1'<br>1.2. 'dependency_2'<br>1.3. 'dependency_3' | 1.1. 'depedency_1_file.rs'<br>1.2. 'dependency_2_file.rs'<br>1.3. 'dependency_3_file.rs' |
| 2. 'function_name_2' | 'function_2_file.rs' | 2.1. 'dependency_1'<br>2.2. 'dependency_2'<br>2.3. 'dependency_3' | 2.1. 'depedency_1_file.rs'<br>2.2. 'dependency_2_file.rs'<br>2.3. 'dependency_3_file.rs' |
| ...                  | ...                  | ...                                                               | ...                                                                                      |

**TABLE 2: Execution Map**

1. 'function_name_1' (call) → 'dependency_1-1' → 'dependency_1-2' → 'dependency_1-3' → ...
2. 'function_name_2' (call) → 'dependency_2-1' → 'dependency_2-2' → 'dependency_2-3' → ...
3. ...

**Risk Assessment**
<!-- 2-3 paragraphs an initial hypothesis and first risk assessment based on these maps. Include what the most critical and risky execution paths are, and the most likely places to find vulnerabilities and attack surfaces within the program's scope. -->

**Top 5 Riskiest Execution Paths**
1. Risky Execution Path 1
2. Risky Execution Path 2
3. Risky Execution Path 3
4. Risky Execution Path 4
5. Risky Execution Path 5

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: recon-notes-exec.md --

### Step 6 - Study Public Findings (Reports, Audits and Known Issues)

Before we start hunting security vulnerabilities and bugs ourselves, we first need to study what others have found before us.

Request the user for public material related to this project (security reports and audits, and known issues). The user's stack has a database with many of these materials in markdown format for higher token efficiency during research and studies.

Web search for more security-related material about this project the user may have missed and output them, with their respective trusted-source links. All external references in this step MUST be properly referenced and should only use trusted sources.

Search for security-related (fixes, bugs, vulnerabilities, improvements, upgrades) issues and pull requests (PRs) in the target repository on Github that were not included by the user.

#### Output

Output a report with your findings that must include:
1. **Summary**, a summary of known attack vectors and patterns, critical/high/medium/low/informative findings from other security researchers, recently fixed bugs, recently implemented features/improvements, and (the most important part) accepted/non-mitigated findings with potential bugs/vulnerabilities/issue that are still live in the code.
2. **TABLE 1: Public Findings**, list all relevant finds and issues in this project with their respective status (fixed, mitigated, accepted, etc)
3. **TABLE 2: Recent Changes**, list relevant recent changes, releases, improvements, and any relevant code activity that impact previous findings from the public reports (for example, that could unintentionally revert a previously audited fix/mitigation)
4. **Attack Vectors and Patterns**, list known attack vectors and patterns for this project and this type of contract

#### Output Example

--- START: recon-notes-find.md ---
==PHASE 2, STEP 6, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Recon Notes Public Findings**
**Project:** 'project-name'
**Version:** 1.0 

**Summary**
<!-- 2-5 paragraphs summary mentioning the execution logic of this contract's core functions, dependencies, types, and other relevant aspects with security research in mind. -->

**TABLE 1: Public Findings**

| Finding        | Status                       | Finding Date | Security Firm/Researcher       |
| -------------- | ---------------------------- | ------------ | ------------------------------ |
| 1. 'Finding 1' | fixed/mitigated/accepted/etc | 'YYYY-MM-DD' | 'firm-name', 'researcher-name' |
| 1. 'Finding 2' | fixed/mitigated/accepted/etc | 'YYYY-MM-DD' | 'firm-name', 'researcher-name' |
| ...            | ...                          | ...          | ...                            |

**TABLE 2: Recent Changes**

| Change     | Commit                  | Impact      | Description                   |
| ---------- | ----------------------- | ----------- | ----------------------------- |
| 'Change 1' | 'commit link on github' | 'Finding X' | 'brief description of impact' |
| 'Change 2' | 'commit link on github' | 'Finding Y' | 'brief description of impact' |
| ...        | ...                     | ...         | ...                           |

**Attack Vectors and Patterns**
1. 'Attack Vector/Pattern 1', 'brief description'.
2. 1. 'Attack Vector/Pattern 2', 'brief description'.
3. ...

**Changelog:**
- YYYY-MM-DD: Notes created.

--- END: recon-notes-find.md --

### Step 7 - Confirm "Phase 2- Recon" Completion

Confirm "Phase 2 - Recon" has been completed and ask the user if they want to start "Phase 3 - Hunt" according to the `instructions/phase3-hunt.md` skill. Ask the user to upload this file.

IMPORTANT: You **should NOT create any strong biases yet!** This was just the recon phase and we must remain open to what we might find and validate during the next phases. 

## Changelog

- 2026-06-22: Create file
- 2026-06-23: Improve templates on "example outputs" to be more general and prevent AI bias to certain patterns
- 2026-07-10 (v1.2): Move v1.1 Steps 5-6 to /tmp/ directory for future reallocation to Phases 3-4 for better fit
- 2026-07-10 (v1.3): Add better Steps 5 and 6 for recon
- 2026-07-11 (v1.4): Improve Step 4 and 5

---

File created on 2026-06-22