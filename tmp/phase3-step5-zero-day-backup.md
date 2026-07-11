### Step 5 - Go Deeper: Zero-Day Hunt

While many vulnerabilities will be on the surface, with obvious misses from security checklists and known attack patterns/vectors, the largest rewards are in the depths of zero-day vulnerabilities.

For that, we will need a bit of creativity and to dive deeper into the unknown.

Read recon notes from function execution paths (`recon-notes-exec.md`) and find broken assumptions, bad executions, misbehavior, and divergences from what is documented (intended) and what may actually happen if an ATTACKER calls a function with malicious intent.

Make me proud!

#### Output
Use the same output template from Step 4. It should include:

1. **Findings**, a 2-4 paragraph summary describing your findings.
2. **TABLE 1: Findings**, ranked by severity, the finding, affected elements (functions, types, macros, etc), affected files, impact hypothesis,
3. **Checklist**, with suggested ripgrep commands for user-driven, manual verification locally
4. **Notable observations** and recommendations for the Attack phase (Phase 4)

#### Output Example

--- START: hunt-notes-zero.md ---
==PHASE 3, STEP 5, TASK 1 — YYYY-MM-DD HH:MM:SS==

**NEAR SC Auditor – Hunt Notes Zero-Day**
**Project:** 'project-name'
**Version:** 1.0 

**Findings**
<!-- 2-4 paragraph summary of your findings and relevant observations -->

**TABLE 1: Zero-day Findings**

| Severity                 | Finding            | Affected Elements                           | Affected Files                              | Impact                                |     |
| ------------------------ | ------------------ | ------------------------------------------- | ------------------------------------------- | ------------------------------------- | --- |
| CRITCIAL/HIGH/MEDIUM/LOW | 'Title: Finding 1' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
| CRITCIAL/HIGH/MEDIUM/LOW | 'Title: Finding 2' | - 'element_1-1'<br>- 'element_1-2'<br>- ... | - 'file_1-1.rs'<br>- 'file_1-2.rs'<br>- ... | 'Brief impact hypothesis description' |     |
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

--- END: hunt-notes-zero.md --