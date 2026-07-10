---
name: nearsc-auditor-hunt
version: "1.0"
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

You **should NOT create any strong biases yet!**

### Step 3 - Review the Initial Checklist Results

Make sure the user has gone through the initial checklist manually from "Phase 2 - Recon" and covered all the items there over the first hypotheses based on quickly identified known attack patterns.

Request more details on any interesting finding and internalize that as we move for a more in-depth approach on each item.

Understand that this initial draft is still incomplete and could have both false positives and false negatives. We need to do a lot more work and **should NOT create any strong biases yet!**

### Step 4 - Plan and Structure the Hunting

Moving forward, we will dive into each checklist item independently or (when possible) delegate unique agents (or sub-agents) for specific hunting work at each item for more efficient token usage and context management.

Agents must read the respective resource material for each checklist item and do the proper, careful verification against keywords and code patterns through the entire project's code base and contracts' source code.

Read the NEAR Security Checklist file (`nearsc-auditor/resources/checklists/checklist.md`) first, for a broader overview before organizing the sub agents and delegating their tasks.

Output your own checklist for this project in particular and set priority checks (high, medium, low priority) with suggested key words, patterns, or any other specifics that are relevant for the contract we are currently auditing. You can use the user's findings from Phase 2 but do not limit yourself by them.

**IMPORTANT:** The user can make mistakes and/or miss things.

### Step 5 - 