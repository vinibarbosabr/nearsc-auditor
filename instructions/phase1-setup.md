---
name: nearsc-auditor-setup
version: "1.2"
author: Vini B (@vinibarbosabr)
description: instructions for the nearsc-auditor Phase 1 - Setup. use it together with the orchestrator skill to setup the user enviornment when starting a NEAR smart contract audit in security research and bug bounty hunting activities.
activation:
  - phase 1 near audit
  - setup near audit
tags:
  - near
  - audit
  - security
---
# PHASE 1 - SETUP | NEAR SC Auditor

**Description:** This is the first phase (Phase 1 - Setup) of a NEAR smart contract audit. Use it together with the nearsc-auditor orchestrator skill `nearsc-auditor/SKILL.md` to setup the user environment for security research and bug bounty hunting activities.

## Execution Steps (nearsc-auditor-setup)

Detailed step-by-step execution that must be followed:

### Step 1 - Premises, Methodology, Basic Concepts, and References

Read the SKILL.md file (orchestrator skill) again to understand and internalize our premises, methodology, basic concepts, and references.

### Step 2 - User Input

Print current status as requires by the orchestrator:
==PHASE 1, STEP 2, TASK 1 — YYYY-MM-DD HH:MM:SS==

Request the user input for the following information when missing from prompt. Before requesting, check in the chat if they already exist.

1. Project name
2. Target repository (Github link)
3. Bug bounty program (link)
4. Audit's root directory (assume `~/vinib-audits/nearsc` if none is provided)

### Step 3 - Setup Script

Output inside a code block the following script to run the `setup_audit.py` tool for this project's audit (replace the placeholders).
1. Go to the tool location: `cd ~/nearsc-auditor/tools/`
2. Run the Python script

```Bash
cd ~/nearsc-auditor/tools/ &&
python setup_audit.py \
  --project 'project-name' \
  --repo 'https://github.com/org/repo' \
  --bug-bounty 'https://platform.com/programs/project-name'
```

#### Script Example

```Bash
cd ~/nearsc-auditor/tools/ &&
python setup_audit.py \
  --project LiNEAR \
  --repo https://github.com/linear-protocol/LiNEAR \
  --bug-bounty https://hackenproof.com/programs/linear-protocol
```

### Step 4 - Document Executive Summary

Ask the user to paste the setup_audit.py output in the chat. This is important for proper documentation (we will use this information in other phases).

#### User Input Example

```Bash
=== Setting up audit for: LiNEAR ===

Cloning repository into audit folder...
⚠️  /home/vinib/vinib-audits/nearsc/audit-LiNEAR/code already exists. Skipping clone.

✅ Audit environment created successfully!
📁 Audit folder: /home/vinib/vinib-audits/nearsc/audit-LiNEAR
📄 REPORT.md has been updated with the executive summary.

=== REPORT.md - Executive Summary ===

## 1. Executive Summary

**Project:** LiNEAR
**Repository:** https://github.com/linear-protocol/LiNEAR
**Commit:** 63cd09a
**Branch:** main
**Date:** 2026-06-22
**Auditor:** Vini B
**Bug Bounty Program:** https://hackenproof.com/programs/linear-protocol
**Contract Address:**

### Abstract

=== END ===
```

### Step 5 - Confirm "Phase 1 - Setup" Completion

Confirm "Phase 1 - Setup" has been completed and ask the user if they want to start "Phase 2 - Recon" according to the `instructions/phase2-recon.md` skill. Ask the user to upload this file.

## Changelog

- 2026-06-22: Create file
- 2026-06-22: Skill simplified; complex execution becomes a python tool
- 2026-07-11: Fixed tool path after renaming repo

---

File created on 2026-06-22