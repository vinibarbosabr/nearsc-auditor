//! Rule registry.
//!
//! Every rule is registered explicitly so the v0.1 catalog is auditable in one
//! place. `rules/*.toml` metadata is embedded in later releases; the matcher
//! registry here is the source of truth for what actually runs.

pub mod callback_not_private;
pub mod callback_panic;
pub mod init_ignore_state;
pub mod one_yocto_missing;
pub mod privileged_setter;
pub mod storage_griefing;
pub mod unbounded_iteration;
pub mod unchecked_promise_result;
pub mod upgrade_path;

use syn::visit::Visit;
use syn::{Attribute, Expr};

use crate::engine::FileContext;
use crate::finding::Finding;

/// A rule consumes a parsed file and returns zero or more findings.
pub trait Rule {
    fn id(&self) -> &'static str;
    fn check(&self, context: &FileContext) -> Vec<Finding>;
}

/// Static catalog entry for the v0.1 rule set.
#[derive(serde::Serialize)]
pub struct RuleMeta {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: crate::finding::Severity,
    pub confidence: crate::finding::Confidence,
    /// Matcher module name; `None` marks a planned (not yet implemented) rule.
    pub matcher: Option<&'static str>,
    pub status: &'static str,
    pub refs: &'static [&'static str],
}

/// The v0.1 catalog (plan section 4). Values mirror docs/RULES.md; the parity
/// test below keeps registered matchers and this table in sync.
pub const CATALOG: &[RuleMeta] = &[
    RuleMeta {
        id: "NS001",
        title: "one-yocto-missing-on-transfer",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Spec,
        matcher: Some("one_yocto_missing"),
        status: "shipped",
        refs: &[
            "https://nomicon.io/Standards/Tokens/FungibleToken/Core",
            "https://nomicon.io/Standards/Tokens/NonFungibleToken/Core",
        ],
    },
    RuleMeta {
        id: "NS002",
        title: "callback-not-private",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Spec,
        matcher: Some("callback_not_private"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md"],
    },
    RuleMeta {
        id: "NS003",
        title: "callback-panic-risk",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("callback_panic"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS004",
        title: "unchecked-promise-result",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("unchecked_promise_result"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS005",
        title: "init-ignore-state-unguarded",
        severity: crate::finding::Severity::Critical,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("init_ignore_state"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS006",
        title: "upgrade-path-unguarded",
        severity: crate::finding::Severity::Critical,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("upgrade_path"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS007",
        title: "unbounded-iteration",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("unbounded_iteration"),
        status: "shipped",
        refs: &["https://docs.near.org/"],
    },
    RuleMeta {
        id: "NS008",
        title: "storage-griefing",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("storage_griefing"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/anatomy/optimizations"],
    },
    RuleMeta {
        id: "NS009",
        title: "insecure-randomness",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: None,
        status: "planned Wed 2026-11-11",
        refs: &["https://docs.near.org/"],
    },
    RuleMeta {
        id: "NS010",
        title: "arbitrary-promise-target",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: None,
        status: "planned Wed 2026-11-11",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS011",
        title: "deposit-refund-missing",
        severity: crate::finding::Severity::Low,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: None,
        status: "planned Wed 2026-11-11",
        refs: &["https://docs.near.org/"],
    },
    RuleMeta {
        id: "NS012",
        title: "privileged-setter-unguarded",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("privileged_setter"),
        status: "shipped",
        refs: &["https://docs.near.org/protocol/accounts-contracts/access-keys"],
    },
];

/// Every registered rule, in catalog order. `run_all` and the parity test
/// both consume this slice; there is no parallel id list to drift.
pub fn rules() -> &'static [&'static dyn Rule] {
    &[
        &one_yocto_missing::OneYoctoMissing,
        &callback_not_private::CallbackNotPrivate,
        &callback_panic::CallbackPanic,
        &unchecked_promise_result::UncheckedPromiseResult,
        &init_ignore_state::InitIgnoreState,
        &upgrade_path::UpgradePath,
        &privileged_setter::PrivilegedSetter,
        &unbounded_iteration::UnboundedIteration,
        &storage_griefing::StorageGriefing,
    ]
}

/// Run every registered rule against one file.
pub fn run_all(context: &FileContext) -> Vec<Finding> {
    rules()
        .iter()
        .flat_map(|rule| rule.check(context))
        .collect()
}

/// True when an attribute's path ends with `name` (`#[private]`, `#[init]`, ...).
pub fn last_segment_is(attr: &Attribute, name: &str) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == name)
}

/// The source line at `line` (1-based), trimmed; empty when out of range.
pub fn snippet_at(context: &FileContext, line: usize) -> String {
    context
        .source
        .lines()
        .nth(line.saturating_sub(1))
        .map(|source_line| source_line.trim().to_string())
        .unwrap_or_default()
}

/// Recognize a manual "only the contract itself may call this" guard.
///
/// Matches a body that mentions both `predecessor_account_id` and
/// `current_account_id`, an `assert_self`-style macro, or a macro invocation
/// whose tokens mention both calls (`assert_eq!`, `require!`, ...). Macro bodies
/// are inspected as tokens because `syn` does not expand them.
pub fn body_has_guard(block: &syn::Block) -> bool {
    #[derive(Default)]
    struct GuardVisitor {
        predecessor: bool,
        current: bool,
        assert_self: bool,
    }

    impl<'ast> Visit<'ast> for GuardVisitor {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "predecessor_account_id" {
                self.predecessor = true;
            }
            if call.method == "current_account_id" {
                self.current = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                if let Some(segment) = path.path.segments.last() {
                    if segment.ident == "predecessor_account_id" {
                        self.predecessor = true;
                    }
                    if segment.ident == "current_account_id" {
                        self.current = true;
                    }
                }
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "assert_self")
            {
                self.assert_self = true;
            }
            let tokens = mac.tokens.to_string();
            if tokens.contains("predecessor_account_id") {
                self.predecessor = true;
            }
            if tokens.contains("current_account_id") {
                self.current = true;
            }
            syn::visit::visit_macro(self, mac);
        }
    }

    let mut visitor = GuardVisitor::default();
    visitor.visit_block(block);
    visitor.assert_self || (visitor.predecessor && visitor.current)
}

#[cfg(test)]
mod tests {
    use super::{body_has_guard, rules, CATALOG};

    #[test]
    fn detects_assert_eq_guard() {
        let block: syn::Block = syn::parse_quote!({
            assert_eq!(env::predecessor_account_id(), env::current_account_id());
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn detects_branch_guard() {
        let block: syn::Block = syn::parse_quote!({
            if env::predecessor_account_id() != env::current_account_id() {
                env::panic_str("only self");
            }
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn detects_assert_self_macro() {
        let block: syn::Block = syn::parse_quote!({
            assert_self!();
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn ignores_partial_or_unrelated_bodies() {
        let partial: syn::Block = syn::parse_quote!({
            let caller = env::predecessor_account_id();
        });
        assert!(!body_has_guard(&partial));

        let unrelated: syn::Block = syn::parse_quote!({
            env::log_str("done");
        });
        assert!(!body_has_guard(&unrelated));
    }

    /// Every registered matcher has a catalog entry, and every catalog entry
    /// with a matcher corresponds to a registered rule (docs <-> code parity).
    /// Registered ids are derived from the same slice `run_all` iterates; the
    /// catalog/matcher relationship is what the loops assert.
    #[test]
    fn catalog_matches_the_registered_matchers() {
        let registered: Vec<&str> = rules().iter().map(|rule| rule.id()).collect();

        for id in &registered {
            let entry = CATALOG
                .iter()
                .find(|entry| &entry.id == id)
                .unwrap_or_else(|| panic!("CATALOG missing {id}"));
            assert!(entry.matcher.is_some(), "{id} shipped but marked planned");
        }
        for entry in CATALOG.iter().filter_map(|entry| entry.matcher) {
            assert!(
                registered.contains(
                    &CATALOG
                        .iter()
                        .find(|candidate| candidate.matcher == Some(entry))
                        .expect("entry")
                        .id
                ),
                "CATALOG claims matcher {entry} but run_all does not register a rule using it"
            );
        }
        for entry in CATALOG.iter().filter(|entry| entry.matcher.is_none()) {
            assert!(
                !registered.contains(&entry.id),
                "{} is registered but the catalog marks it planned",
                entry.id
            );
        }
    }
}
