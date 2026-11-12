name: False positive report
description: Report a finding that flags provably safe code
title: "FP: <rule id> on <project>/<file>"
labels: ["audit-finding"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for testing nearsc against real contracts. Read the policy first:
        https://github.com/vinibarbosabr/nearsc-auditor/blob/main/docs/FALSE-POSITIVES.md

        A false positive means the code is **provably safe from the source**:
        the guard the rule wants exists in a spelling the matcher misses, or the
        assumed protocol semantics do not apply. "Looks fine" or "works in
        production" is not enough — quote the evidence.
  - type: input
    id: rule
    attributes:
      label: Rule id
      placeholder: NS012
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: nearsc version
      description: Output of `nearsc --version`, or the commit you built
      placeholder: "0.1.2"
    validations:
      required: true
  - type: textarea
    id: location
    attributes:
      label: Finding location
      description: The finding line from the scan output (rule, file:line, message)
      placeholder: "MEDIUM NS012 src/lib.rs:46 public setter `set_owner` ..."
    validations:
      required: true
  - type: textarea
    id: evidence
    attributes:
      label: Why this is a false positive (the evidence)
      description: Where does the guard/check the rule wants actually live? A same-file helper? A delegated standards implementation? Documented protocol semantics (e.g. panics auto-refund)?
      placeholder: |
        `set_owner` calls `self.assert_owner()` (src/lib.rs:47), defined at
        src/lib.rs:244, which asserts `self.get_owner() == env::predecessor_account_id()`.
    validations:
      required: true
  - type: textarea
    id: snippet
    attributes:
      label: Minimal reproducer (optional, helps a lot)
      description: The smallest fixture-shaped snippet that reproduces the FP (see tests/fixtures/ for the shape). Accepted FPs become negative-control fixtures.
  - type: checkboxes
    id: checks
    attributes:
      label: Triage checklist (reporter)
      options:
        - label: I verified the finding in the target's current source (not an old commit)
        - label: I read the rule's detection and false-positive notes in docs/RULES.md
        - label: I identified where the guard/semantics the rule wants actually lives
