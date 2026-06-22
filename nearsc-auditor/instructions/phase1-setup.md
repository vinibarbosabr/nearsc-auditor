---
name: nearsc-auditor-setup
version: "1.0"
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

Request the user input for the following information when missing from prompt. Before requesting, check in the chat if they already exist.

1. Project name
2. Target repository (Github link)
3. Bug bounty program (link)
4. Audit's root directory (assume `~/vinib-audits/` if none is provided)

### Step 3 - Setup Script

Output inside a code block the following script to setup this audit's environment. The user (I, Vini) will copy and paste it directly into the terminal. It must be ready to copy, paste, and execute. Replace the placeholders accordingly. Use the proper language according to the user's spec defined below.

#### Script methodology

1. Clone the repository: `git clone "'github-link'"`
2. Print (`echo`) the last commit (short SHA) and branch cloned
3. Go to the audit's root directory: `cd ~/'root-directory'/` 
4. Create the audit directory for this specific project: `mkdir nearsc-audit-'project-name'`
5. Go to the now created directory: `cd nearsc-audit-'project-name'`
6. Copy and rename the report template file to this directory: `cp ~/nearsc-auditor/report-template.md REPORT.md`
7. Print (`echo`) project-specific information to the REPORT.md's executive summary, that I can then copy from the terminal and manually paste inside the file.
	1. **Project:** <!-- project-name -->
	2. **Repository:** <!-- org/repo --> 
	3. **Commit:** <!-- short SHA --> 
	4. **Branch:** <!-- branch name --> 
	5. **Date:** <!-- YYYY-MM-DD --> 
	6. **Auditor:** <!-- Agent or human name --> 
	7. **Bug Bounty Program:** <!-- platform/program --> 
	8. **Contract Address:** <!-- On-chain contract address --> 

```bash
git clone 'github-link' &&
cd "$(basename 'github-link' .git)" &&
BRANCH=$(git branch --show-current) &&
COMMIT=$(git rev-parse --short HEAD) &&
cd ~/'root-directory' &&
mkdir -p nearsc-audit-'project-name' &&
cd nearsc-audit-'project-name' &&
cp ~/nearsc-auditor/report-template.md REPORT.md &&
echo "" &&
echo "✅ Audit folder created successfully." &&
echo "" &&
echo "=== COPY THE LINES BELOW INTO YOUR REPORT.md ===" &&
echo "" &&
echo "**Project:** 'project-name'" &&
echo "**Repository:** 'github-link'" &&
echo "**Commit:** $COMMIT" &&
echo "**Branch:** $BRANCH" &&
echo "**Date:** $(date +%Y-%m-%d)" &&
echo "**Auditor:** Vini B" &&
echo "**Bug Bounty Program:** 'bug-bounty-link'" &&
echo "**Contract Address:** " &&
echo "" &&
echo "=== END ==="
```

#### Script Example

```bash

```

## User's Spec


## Changelog

- 2026-06-22: Create file

---

File created on 2026-06-22