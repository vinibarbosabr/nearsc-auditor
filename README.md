# NEAR SC Auditor

**Senior-grade, AI-augmented security research & bug bounty stack for NEAR Protocol smart contracts.**

> **Hybrid AI + Human workflow** for systematic, high-signal vulnerability hunting on NEAR smart contracts (Rust → WASM). Built for ethical whitehats, bug bounty hunters, and security researchers who want reproducible, phased, and thorough audits.

---

## Overview

nearsc-auditor is a complete, self-contained stack designed to turn AI Agents into a senior NEAR security researcher.

It enforces a strict, phased methodology that mirrors real-world bug bounty workflows while remaining token-efficient and human-in-the-loop.

### Core Philosophy

- **Assume bugs exist** — if we haven't found them, we missed something.
- **Hybrid approach** — AI does the heavy lifting (mapping, hunting, pattern matching); human validates, prioritizes, and decides.
- **Attacker mindset** in Phase 4 — only real, demonstrable, exploitable issues matter.
- **Full documentation** of every phase so findings are reproducible and report-ready.
- **NEAR-specific** — deep understanding of async promises, storage staking, 1 yoctoNEAR checks, callbacks, Nightshade, etc.

The stack is used in every audit conversation. The AI is instructed to always start by reading SKILL.md + this README.md.

---
## Stack Structure (in order of importance)

```Text
nearsc-auditor/
├── README.md                          # ← YOU ARE HERE. Stack map & reference (this file)
├── SKILL.md                           # Orchestrator skill (v1.4) — the brain. Always read first.
│
├── instructions/                      # Phased execution playbooks
│   ├── phase1-setup.md                # Environment bootstrap + executive summary
│   ├── phase2-recon.md                # Map project, source, execution paths, public findings
│   ├── phase3-hunt.md                 # Checklist + known attack patterns + zero-day hunt
│   └── phase4-attack.md               # Attacker mindset, attack surface map, PoCs (workspaces-rs)
│
├── resources/                         # Knowledge base (read fully when referenced)
│   ├── near-docs/                     # NEAR-specific security resources
│   │   ├── security-checklist.md      # Official + extended security checklist
│   │   ├── security-storage.md        # Storage cost / griefing attacks
│   │   ├── security-callbacks.md      # Cross-contract calls & callback safety
│   │   ├── security-one_yocto.md      # 1 yoctoNEAR authorization pattern
│   │   ├── security-sybil.md          # Sybil / account spam vectors
│   │   ├── security-frontrunning.md   # Front-running & MEV-style issues
│   │   ├── security-reentrancy.md     # Reentrancy in async model
│   │   └── security-random.md         # Insecure randomness
│   │
│   ├── public-reports/                # Curated real audit reports (markdown for token efficiency)
│   │   ├── burrowland/
│   │   ├── linear-protocol/
│   │   └── sputnikdao2/
│   │
│   ├── severity/                      # Severity classification frameworks
│   │   ├── cvss-4.0.md                # Full CVSS 4.0 for when program has no custom matrix
│   │   └── hackenproof-vuln-class-scs.md
│   │
│   └── templates/
│       └── report-template.md         # Final report skeleton
│
├── tools/                             # Automation helpers
│   ├── setup_audit.py                 # One-command audit environment bootstrapper
│   └── near-workspaces/
│       └── workspaces-rs-README.md    # Reference for writing PoCs (preferred framework)
│
└── tmp/                               # Scratch / temporary notes (gitignored in real usage)
```

Every phase produces versioned markdown notes (`recon-notes-*.md`, `hunt-notes-*.md`, `attack-notes-*.md`, `poc-*.md`) that feed the next phase and the final report.

---
## How to Use This Stack (in a new audit conversation)

1. Start a fresh conversation (or project chat) dedicated to one target.
2. Upload / attach SKILL.md + the relevant phase instruction + any needed resources.
3. Tell the Agent:
    
    > "Audit NEAR project X using nearsc-auditor. Target: 'repo' | Bounty: 'link'"
    
4. Grok will:
    - Read SKILL.md
    - Read this README.md
    - Output status: ==PHASE X, STEP Y, TASK Z — YYYY-MM-DD HH:MM:SS==
    - Follow the exact steps in the current phase file
5. Provide files / command outputs when requested.
6. Iterate until Phase 4 PoCs are solid → write the final report.

The AI is instructed to stay token-efficient in chat and dump full notes in the `--- START: filename.md ---` format so they can be saved directly.

---

## Key NEAR Security Concepts (quick reminder)

- All cross-contract calls are **async** (promises/receipts). No atomicity.
- Storage is staked (~1 NEAR / 100 KiB). Storage griefing is real.
- 1 yoctoNEAR attachment is the standard "only the user can call this" pattern.
- Callbacks must be #[private], handle failures, refund, and leave the contract in a safe state.
- Owner/DAO upgrade paths and re-initialization are classic high-severity surfaces.
- Prefer workspaces-rs for PoCs (matches most target test suites).

Full concepts live in SKILL.md → "NEAR Basic Concepts".

---

## Contributing / Extending the Stack

This stack is living. When you find:

- A new attack pattern → add resources/near-docs/security-xxx.md
- A good public report → add to resources/public-reports/'project'/
- Improvements to any phase → edit the corresponding instructions/phaseN-*.md and bump version in frontmatter
- Better PoC helpers → extend tools/

Always keep the orchestrator (SKILL.md) and this README.md in sync.

---

## Author

**Vini B** (@vinibarbosabr) Blockchain security researcher & bug bounty hunter focused on NEAR.

---

## Changelog

- **2026-07-11** — Initial full README created (stack structure + usage guide)
- 2026-07-10 — Phase 3 & Phase 4 stabilized, Phase 5 merged into 4
- 2026-06-22 — Project born (SKILL + Phase 1)