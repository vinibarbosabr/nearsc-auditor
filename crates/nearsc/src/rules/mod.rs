//! Rule registry.
//!
//! Every rule is registered explicitly so the v0.1 catalog is auditable in one
//! place. `rules/*.toml` metadata is embedded in later releases; the matcher
//! registry here is the source of truth for what actually runs.

pub mod callback_not_private;
pub mod callback_panic;
pub mod init_ignore_state;
pub mod one_yocto_missing;
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

/// Run every registered rule against one file.
pub fn run_all(context: &FileContext) -> Vec<Finding> {
    let rules: &[&dyn Rule] = &[
        &one_yocto_missing::OneYoctoMissing,
        &callback_not_private::CallbackNotPrivate,
        &callback_panic::CallbackPanic,
        &unchecked_promise_result::UncheckedPromiseResult,
        &init_ignore_state::InitIgnoreState,
        &upgrade_path::UpgradePath,
    ];
    rules.iter().flat_map(|rule| rule.check(context)).collect()
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
    use super::body_has_guard;

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
}
