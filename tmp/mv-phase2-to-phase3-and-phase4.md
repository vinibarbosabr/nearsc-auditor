this is a temporary file.

backing up steps previously in Phase 2 that will be better used in Phase 3 and Phase 4:

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

STEP X -- ATTACK 

