---
name: nearsc-auditor-recon
version: "1.0"
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
	1. list the most important functions and provide a one-line explanation on what each of them does.
	2. i won't set any minimum or maximum functions, as you need to be able to effectively filter out the noise, while including all functions that matter.
4. add any worthy notable observations to guide us in the next phase.
5. finish with a summary recommendation for Phase 3 - Hunt.

#### Output Example:

--- START: recon-notes-map.md ---

**Audit Recon Map – LiNEAR (Liquid Staking Contract)**

From `cloc .`:

| Language | Files | Blank | Comment | Code  |
| -------- | ----- | ----- | ------- | ----- |
| Rust     | 33    | 963   | 1,142   | 6,395 |

- The main contract logic lives in **`contracts/linear/src/`** (this is the production code).
- Mock contracts (`mock-*`) are only for testing and can be deprioritized during the security review.
---
**Simplified Project Structure + Priority Files Focusing on the real contract (`contracts/linear/src/`):**
```bash
contracts/linear/src/
├── lib.rs                  # ← HIGH PRIORITY (Main contract struct + initialization)
├── stake.rs                # ← HIGH PRIORITY (Core user staking logic)
├── epoch_actions.rs        # ← HIGH PRIORITY (Epoch staking/unstaking with validators)
├── validator_pool.rs       # ← HIGH PRIORITY (Validator management - largest file)
├── owner.rs                # ← HIGH PRIORITY (Admin/Owner functions + pause)
├── upgrade.rs              # ← HIGH PRIORITY (Contract upgrade & migration)
├── fungible_token/
│   ├── core.rs             # ← HIGH PRIORITY (ft_transfer, ft_resolve_transfer)
│   ├── storage.rs          # ← MEDIUM (Storage staking for FT)
│   └── metadata.rs
├── view.rs                 # View functions (read-only)
├── internal.rs             # Internal helper functions
├── events.rs
├── utils.rs
├── metadata.rs
├── account.rs
├── types.rs
├── errors.rs
└── legacy.rs               # Old contract versions (migration)
```

**Files to Prioritize in Phase 3 (HUNT)**

|Priority|File|Reason|
|---|---|---|
|Critical|stake.rs|Main user entrypoints (deposit, stake, unstake, withdraw)|
|Critical|epoch_actions.rs|Core logic that interacts with validators every epoch|
|Critical|validator_pool.rs|Manages all validators, weights, draining, syncing balances|
|Critical|owner.rs|Admin functions (pause, set owner, managers, beneficiaries, whitelist)|
|Critical|upgrade.rs|Contract upgrade mechanism|
|High|fungible_token/core.rs|ft_transfer implementation|
|High|lib.rs|Contract struct definition and new()|
|Medium|internal.rs|Internal logic (worth reviewing)|
|Low|view.rs, events.rs|Mostly read-only + events|


---
**Core Public Functions (Main Attack Surface)**

| Function                       | File                   | Type       | Description                                                      |
| ------------------------------ | ---------------------- | ---------- | ---------------------------------------------------------------- |
| deposit                        | stake.rs               | Payable    | Deposit NEAR into the contract (increases share balance)         |
| deposit_and_stake              | stake.rs               | Payable    | Deposit + immediately stake NEAR                                 |
| stake                          | stake.rs               | Payable    | Stake previously deposited NEAR                                  |
| unstake                        | stake.rs               | -          | Unstake a specific amount of stNEAR                              |
| unstake_all                    | stake.rs               | -          | Unstake all stNEAR                                               |
| withdraw                       | stake.rs               | -          | Withdraw unstaked NEAR after unstaking period                    |
| withdraw_all                   | stake.rs               | -          | Withdraw all available unstaked NEAR                             |
| epoch_stake                    | epoch_actions.rs       | -          | Stakes NEAR to selected validators (called periodically)         |
| epoch_unstake                  | epoch_actions.rs       | -          | Unstakes from validators                                         |
| epoch_update_rewards           | epoch_actions.rs       | -          | Claims and distributes rewards from validators                   |
| epoch_withdraw                 | epoch_actions.rs       | -          | Withdraws unstaked funds from validators                         |
| set_owner                      | owner.rs               | Owner only | Changes contract owner                                           |
| pause / resume                 | owner.rs               | Owner only | Emergency pause mechanism                                        |
| add_manager / remove_manager   | owner.rs               | Owner only | Manage privileged accounts                                       |
| upgrade                        | upgrade.rs             | Owner only | Upgrades the contract code                                       |
| migrate                        | upgrade.rs             | -          | Migration function after upgrade                                 |
| ft_transfer                    | fungible_token/core.rs | Payable    | Transfer LiNEAR tokens                                           |
| validator_staked_callback etc. | epoch_actions.rs       | Private    | Callbacks from validator interactions (important for reentrancy) |

**Notable Observations**: 
- **Core business logic** is concentrated in `stake.rs` + `epoch_actions.rs` + `validator_pool.rs`.
- The contract follows a **liquid staking** model (users get LiNEAR tokens representing staked NEAR).
- There is a **pause mechanism** and **owner + managers** system.
- Validator interaction happens asynchronously through **epoch actions** and callbacks
- — this is a high-risk area (reward distribution, draining, balance syncing).
- Several functions in `validator_pool.rs` are marked `#[near_bindgen]` (especially draining functions).
- ---
**Summary Recommendation**
**Focus your Phase 3 (HUNT) on these areas first:**
1. **Staking flow** (`stake.rs`) — deposit/stake/unstake/withdraw logic
2. **Epoch actions** (`epoch_actions.rs`) — especially reward claiming and validator callbacks
3. **Validator Pool** (`validator_pool.rs`) — weight management, draining, balance syncing
4. **Owner/Admin functions** (`owner.rs`) — privilege escalation and pause logic
5. **Upgrade path** (`upgrade.rs` + `migrate`)
6. **Fungible Token implementation** (`fungible_token/core.rs` + `storage.rs`).

--- END: recon-notes-map.md --

### Step 5 - Attack Surface Map and Checklist Draft

Ask the user for confirmation to create a more detailed attack surface map and a checklist for these specific files and first recon notes.

1. Create a table with the high-risk areas (ranked by priority): Rank, Area, Files Involved, Risk Level, Main Concern.
2. Create a detailed HUNT Checklist for each file that will help us in the next Phase (3). It will serve as a brief draft that must be improved later (we will dive deeper into each item individually).
	1. Start with the file name,
	2. follo with a 3-word explainer, and
	3. add a priority rank/severity classification.
	4. Then list focus areas and the security checklist
3. Create a table with general things to watch for across all files, with: Category, What to Look For, Severity.

#### Example Output

--- START: recon-notes-check.md ---

**LiNEAR Attack Surface Map & Pre-Phase 3 HUNT Checklist**

**High-Risk Areas (Ranked by Priority)**

| Rank | Area                                  | Files Involved                      | Risk Level | Main Concern                                         |
| ---- | ------------------------------------- | ----------------------------------- | ---------- | ---------------------------------------------------- |
| 1    | Epoch Actions & Validator Interaction | epoch_actions.rs, validator_pool.rs | Critical   | Async callbacks, reward distribution, draining logic |
| 2    | Staking / Unstaking Flow              | stake.rs                            | Critical   | Core user funds movement                             |
| 3    | Access Control & Admin                | owner.rs, lib.rs                    | High       | Privilege escalation, pause bypass                   |
| 4    | Contract Upgrade                      | upgrade.rs, legacy.rs               | High       | Storage migration, broken state after upgrade        |
| 5    | Fungible Token (LiNEAR)               | fungible_token/core.rs, storage.rs  | High       | NEP-141 compliance + share accounting                |
| 6    | Internal Accounting                   | internal.rs, validator_pool.rs      | Medium     | Balance inconsistencies                              |

---
**Detailed HUNT Checklist (Pre-Phase 3)**

**A. `stake.rs` – Core Staking Logic** (Highest Priority)

**Focus Areas:**
- `deposit()`, `deposit_and_stake()`, `stake()`, `unstake()`, `withdraw()`
- Share calculation logic (`staked_amount_from_num_shares`)
- Relationship between deposited NEAR and minted LiNEAR shares

**Checklist:**
- [ ] Is there proper validation on `amount > 0` in all payable functions?
- [ ] Can a user withdraw more than they should be able to? (rounding issues)
- [ ] Are there any reentrancy risks during `deposit_and_stake`?
- [ ] Check if `ping()` is correctly handled (or intentionally disabled).
- [ ] Verify that unstaking properly reduces the user’s share balance.
- [ ] Look for missing checks when the contract is paused.

---
**B. `epoch_actions.rs` – Epoch Validator Interaction** (Critical) 

This is likely the **most complex and risky** part of the contract. 

**Checklist:**
- [ ] Review all callback functions (`validator_staked_callback`, `validator_unstaked_callback`, etc.).
- [ ] Are callbacks properly protected with `#[private]` or `assert_private()`?
- [ ] Can an attacker manipulate callbacks (e.g., by calling them directly)?
- [ ] Check reward distribution logic — is it fair and correctly calculated?
- [ ] Look for potential issues in `epoch_stake` / `epoch_unstake` when some validators fail.
- [ ] Verify draining logic (`drain_unstake`, `drain_withdraw`) — especially access control.
- [ ] Check for gas-related issues in long promise chains.

---
**C. `validator_pool.rs` – Validator Management**
This file is large (~104k) and contains a lot of logic. 

**Checklist:**
- [ ] Review how validators are added/removed and how weights are updated.
- [ ] Check `drain_unstake` and `drain_withdraw` functions carefully.
- [ ] Are there proper checks before changing validator weights?
- [ ] Look for off-by-one or rounding errors in stake distribution across validators.
- [ ] Verify `sync_balance_from_validator` and related sync logic.
- [ ] Check if a malicious validator can cause issues (e.g., by returning wrong balances).
---
**D. `owner.rs` – Admin Functions** **Checklist:**
- [ ] Verify all admin functions have proper `assert_owner()` or `assert_manager()` checks.
- [ ] Can the owner (or managers) drain funds or steal value?
- [ ] Review the `pause()` / `resume()` mechanism — is it properly enforced everywhere it should be?
- [ ] Check beneficiary and treasury logic (`set_beneficiary`, `set_treasury`).
- [ ] Look for functions that should be owner-only but aren’t.

---
**E. `upgrade.rs` + `lib.rs` – Upgrade & Initialization** 

**Checklist:**
- [ ] Review the `upgrade()` function.
- [ ] Check the `migrate()` function — does it properly handle storage migration?
- [ ] Are there any storage layout changes between versions that could break state?
- [ ] Verify that `new()` and `migrate()` cannot be called maliciously after deployment.
- [ ] Check for `PromiseOrValue` usage in upgrade flow.

---
**F. `fungible_token/core.rs` – LiNEAR Token** **Checklist:**
- [ ] Verify `ft_transfer` implementation follows NEP-141 correctly.
- [ ] Check `ft_resolve_transfer` for proper balance adjustments.
- [ ] Look for any custom logic in `ft_transfer` that could be exploited.
- [ ] Ensure storage staking (`storage.rs`) is correctly implemented.

---
**General Things to Watch For (Across All Files)**

| Category           | What to Look For                                    | Severity |
| ------------------ | --------------------------------------------------- | -------- |
| Access Control     | Missing or weak assert_owner, assert_private        | High     |
| Callbacks          | Unprotected or incorrectly protected callbacks      | Critical |
| Accounting         | Share vs actual staked balance mismatches           | High     |
| Pause Mechanism    | Can critical functions still be called when paused? | High     |
| Integer / Rounding | Share calculations, reward distribution             | Medium   |
| Reentrancy         | Especially in payable + promise chains              | High     |
| Upgrade Safety     | Storage migration + state compatibility             | High     |
| Validator Trust    | Over-reliance on validator responses                | High     |

--- END: recon-notes-check.md ---

### Step 6 - Known Attack Surfaces and Hypothesis List

Generate a vulnerability hypothesis list with common attack patterns for this type of contract.

Create one table for each severity risk (CRITICAL/HIGH/MEDIUM/LOW), with # (list id), hypothesis, description, why it's relevant, key files to check, likelihood.

Finish with a recommended focus order for phase 3.

#### Example Output

--- START: recon-notes-atk.md ---

**Critical**

| #   | Hypothesis                                              | Description                                                                                                                                             | Why It's Relevant                                                                              | Key Files to Check                  | Likelihood  |
| --- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------- | ----------- |
| 1   | Callback Manipulation / Unauthorized Callback Execution | An attacker can directly call callback functions (e.g. validator_staked_callback, validator_unstaked_callback) without going through the intended flow. | NEAR contracts rely heavily on async callbacks. Many contracts fail to properly restrict them. | epoch_actions.rs, validator_pool.rs | High        |
| 2   | Incorrect Reward Distribution / Accounting              | Rewards from validators are not correctly distributed or are lost/stolen due to flawed logic in epoch_update_rewards.                                   | Liquid staking contracts are extremely sensitive to reward accounting errors.                  | epoch_actions.rs, validator_pool.rs | High        |
| 3   | Validator Draining Attack                               | An attacker (or compromised manager/owner) can abuse drain_unstake / drain_withdraw to steal funds from validators.                                     | The contract has explicit draining functionality.                                              | validator_pool.rs, owner.rs         | Medium-High |
| 4   | Reentrancy via Cross-Contract Calls                     | A malicious validator or another contract can re-enter during deposit_and_stake, epoch_stake, or callback execution.                                    | NEAR's async model makes reentrancy possible even without classic reentrancy patterns.         |                                     |             |

**High**

|#|Hypothesis|Description|Why It's Relevant|Key Files to Check|Likelihood|
|---|---|---|---|---|---|
|5|Pause Mechanism Bypass|Critical functions (especially staking/unstaking) can still be executed even when the contract is paused.|Many contracts implement pause incorrectly or incompletely.|owner.rs, stake.rs, epoch_actions.rs|Medium|
|6|Insufficient Access Control on Admin Functions|Manager or owner functions lack proper authorization checks, allowing unauthorized users to perform privileged actions.|The contract has both owner and manager roles.|owner.rs|Medium|
|7|Broken Storage Migration After Upgrade|The migrate() function does not correctly handle state changes from previous versions, leading to corrupted state or loss of funds.|The contract has multiple legacy versions (legacy.rs).|upgrade.rs, legacy.rs, lib.rs|High|
|8|Share Calculation / Rounding Exploit|An attacker can manipulate share calculations to mint more LiNEAR than they should or withdraw more NEAR than deposited.|Common issue in liquid staking protocols.|stake.rs, internal.rs|Medium|
|9|Validator Balance Sync Manipulation|A validator can return manipulated balances during sync_balance_from_validator or similar callbacks, causing incorrect accounting.|The contract interacts with many external validators.|validator_pool.rs, epoch_actions.rs|Medium|

**Medium**

|#|Hypothesis|Description|Why It's Relevant|Key Files to Check|Likelihood|
|---|---|---|---|---|---|
|10|Improper Handling of Failed Epoch Actions|If epoch_stake or epoch_unstake partially fails, the contract enters an inconsistent state.|Epoch actions involve multiple validators and promises.|epoch_actions.rs|Medium|
|11|Fungible Token Standard Violation (NEP-141)|The ft_transfer or ft_resolve_transfer implementation does not fully comply with the standard, allowing token theft or freezing.|LiNEAR is a fungible token.|fungible_token/core.rs|Low-Medium|
|12|Treasury / Beneficiary Drain|The owner or managers can redirect rewards or funds to themselves via set_treasury or set_beneficiary.|These are privileged functions that affect value distribution.|owner.rs|Medium|
|13|Front-running / MEV on Epoch Actions|An attacker can front-run epoch_stake / epoch_unstake calls to gain unfair advantage.|Less severe on NEAR than Ethereum, but still worth checking.|epoch_actions.rs|Low-Medium|
|14|Missing or Weak Input Validation|Functions accept invalid parameters (e.g., zero amounts, invalid account IDs, or exceeding limits).|Basic but still frequently missed.|stake.rs, owner.rs|Medium|

**Key Attack Patterns Specific to this Contract Type**

| Attack Pattern          | Description                                                           | Relevant Files             | Severity |
| ----------------------- | --------------------------------------------------------------------- | -------------------------- | -------- |
| Callback Injection      | Calling callback functions directly with crafted data                 | epoch_actions.rs           | Critical |
| Reward Skimming / Theft | Manipulating reward distribution logic                                | epoch_actions.rs           | High     |
| Validator Draining      | Abusing drain functions to extract funds from validators              | validator_pool.rs          | High     |
| Share Inflation         | Exploiting rounding or calculation errors to mint extra shares        | stake.rs                   | High     |
| Admin Privilege Abuse   | Using owner/manager functions to steal funds or break the protocol    | owner.rs                   | High     |
| Upgrade Hijacking       | Upgrading to a malicious contract or breaking state during migration  | upgrade.rs                 | High     |
| Paused State Bypass     | Executing sensitive operations while the contract claims to be paused | owner.rs + business logic  | High     |
| Asynchronous Reentrancy | Using NEAR's promise/callback system to re-enter critical functions   | stake.rs, epoch_actions.rs | High     |
**Recommended Focus Order for Phase 3 (HUNT)**
- Epoch Actions + Callbacks (epoch_actions.rs)
- Validator Pool & Draining (validator_pool.rs)
- Staking Core Logic (stake.rs)
- Access Control & Pause (owner.rs)
- Upgrade & Migration (upgrade.rs)
- Fungible Token Implementation

--- END: recon-notes-atk.md ---

### Step 7 - Confirm "Phase 2- Recon" Completion

Confirm "Phase 2 - Recon" has been completed and ask the user if they want to start "Phase 3 - Hunt" according to the `instructions/phase3-hunt.md` skill.

## Changelog

- 2026-06-22: Create file
- TODO: create templates for the example output files and reference the example to each file to keep this instruction skill clean.

---

File created on 2026-06-22