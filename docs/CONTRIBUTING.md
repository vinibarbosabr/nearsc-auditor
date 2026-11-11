# Contributing

> **Status:** guide for the planned v0.1 (2026-11-09). Dev setup commands assume the workspace described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Dev setup

```bash
git clone https://github.com/vinibarbosabr/nearsc-auditor
cd nearsc-auditor
cargo build
cargo test
```

Requirements: Rust stable (2021 edition). No other toolchain dependencies.

## Before every PR

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same three commands plus a dogfood scan of `examples/vulnerable-contract`.

## Add a rule

1. **Pick the next id.** `NS0xx`, sequential. Check the `CATALOG` table for collisions.
2. **Add a catalog entry** in `crates/nearsc/src/rules/mod.rs`: id, title, severity, confidence, refs, matcher. Then write the matcher in the same tree. **Status:** shipped; the `CATALOG` table is the source of truth and the parity test keeps it in sync with the registered matchers.
3. **Implement the matcher.** `crates/nearsc/src/rules/ns0xx.rs`, registered in the registry. Pure function over `FileContext`, no I/O, no network.
4. **Add fixtures.** `tests/fixtures/NS0xx/vuln.rs` must emit exactly that rule id; `fixed.rs` must emit nothing.
5. **Add a per-rule integration test** asserting the fixture pair, severity, and confidence (see `crates/nearsc/tests/ns002.rs`).
6. **Document it.** Add the rule section to [RULES.md](RULES.md) with why, detection, false positives, and refs.
7. **PR.** One rule per PR. Include the fixture pair and the docs change.

### Rule quality bar

- One behavior per fixture pair.
- Every finding has a fix and a reference.
- Heuristic rules say so and ask for review in the message.
- No rule that cannot be tested.

## Add a KB entry

1. Pick `crates/nearsc/data/patterns/`, `crates/nearsc/data/audits/`, or `crates/nearsc/data/postmortems/`.
2. Add the frontmatter: title, kind, source (required for audits/postmortems), retrieved date, confidence, tags.
3. Summarize; link the source; never copy third-party text wholesale.
4. Rebuild `crates/nearsc/data/index.json`:

   ```bash
   cargo run -p nearsc -- kb-index > crates/nearsc/data/index.json
   ```

   `crates/nearsc/tests/kb.rs` (`index_json_is_in_sync_with_data_directory`) fails if the checked-in index drifts from `data/`, so CI blocks an unsynced index. The data ships embedded in the binary (D-005); the tests also pin the shipped entry counts.
5. PR with the source link in the description.

## Commit style

Short imperative lowercase, one logical change per commit. Examples:

```
feat: add ns002 callback-not-private matcher
docs: document storage-griefing detection
fix: stable sort for findings on same line
```

## Review checklist (for maintainers)

- [ ] Fixture pair proves the rule works and does not over-trigger.
- [ ] CATALOG and matchers are in sync (parity test passes).
- [ ] RULES.md updated.
- [ ] No network, no execution, no secrets in the change.
- [ ] Determinism preserved (no timestamps or random ordering in findings).
- [ ] `cargo fmt`, `clippy`, `test` green.

## Scope guidance

Nearsc is a static analyzer with a knowledge base. If a proposal needs runtime execution, fuzzing, or model calls, it belongs in a companion tool, not the engine. Open an issue to discuss.
