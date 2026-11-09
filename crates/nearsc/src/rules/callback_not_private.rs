//! NS002: callback not marked `#[private]`.
//!
//! A callback that any account can invoke can be faked. On NEAR, callbacks are
//! ordinary methods; `#[private]` (or an explicit predecessor assertion) is what
//! restricts them to the contract itself.

use syn::visit::Visit;
use syn::{Attribute, Expr, ImplItemFn, ItemFn};

use super::Rule;
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct CallbackNotPrivate;

const RULE_ID: &str = "NS002";
const TITLE: &str = "Callback not marked #[private]";
const REFS: &[&str] =
    &["https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md"];

impl Rule for CallbackNotPrivate {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn check(&self, context: &FileContext) -> Vec<Finding> {
        let mut collector = Collector::default();
        collector.visit_file(&context.ast);
        collector.into_findings(context)
    }
}

#[derive(Default)]
struct Collector {
    /// Names passed to `.then(...)`.
    then_callbacks: Vec<String>,
    /// Every function defined in the file, with the attributes we care about.
    candidates: Vec<FnInfo>,
}

struct FnInfo {
    name: String,
    has_private: bool,
    has_manual_guard: bool,
    is_callback_attr: bool,
    line: usize,
    column: usize,
}

impl Collector {
    fn into_findings(self, context: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for candidate in &self.candidates {
            let used_as_callback = candidate.is_callback_attr
                || self
                    .then_callbacks
                    .iter()
                    .any(|name| name == &candidate.name);
            if used_as_callback && !candidate.has_private && !candidate.has_manual_guard {
                findings.push(Finding {
                    rule_id: RULE_ID,
                    title: TITLE,
                    severity: Severity::High,
                    confidence: Confidence::Spec,
                    file: context.file.clone(),
                    line: candidate.line,
                    column: candidate.column,
                    snippet: snippet_at(context, candidate.line),
                    message: format!(
                        "callback `{}` can be invoked by any account; add #[private] or assert predecessor == current_account_id",
                        candidate.name
                    ),
                    refs: REFS,
                });
            }
        }
        findings
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[Attribute], body: &syn::Block) {
        let start = ident.span().start();
        self.candidates.push(FnInfo {
            name: ident.to_string(),
            has_private: attrs.iter().any(|attr| last_segment_is(attr, "private")),
            has_manual_guard: body_has_manual_guard(body),
            is_callback_attr: attrs.iter().any(|attr| {
                last_segment_is(attr, "callback")
                    || last_segment_is(attr, "callback_result")
                    || last_segment_is(attr, "callback_unwrap")
                    || last_segment_is(attr, "callback_vec")
            }),
            line: start.line,
            column: start.column + 1,
        });
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "then" {
            if let Some(arg) = call.args.first() {
                if let Some(name) = callback_name(arg) {
                    self.then_callbacks.push(name);
                }
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_impl_item_fn(self, item);
    }
}

/// Recognize a manual "only the contract itself may call this" guard.
///
/// Matches a body that mentions both `predecessor_account_id` and
/// `current_account_id`, an `assert_self`-style macro, or a macro invocation
/// whose tokens mention both calls (`assert_eq!`, `require!`, ...). Macro bodies
/// are inspected as tokens because `syn` does not expand them.
fn body_has_manual_guard(block: &syn::Block) -> bool {
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

/// Extract the callback function name from the argument to `.then(...)`.
/// Handles `.then(on_transfer)`, `.then(Self::on_transfer)`, and the near-sdk
/// idiom `.then(Self::ext(env::current_account_id()).on_transfer(...))`.
fn callback_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::MethodCall(call) => Some(call.method.to_string()),
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn last_segment_is(attr: &Attribute, name: &str) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == name)
}

fn snippet_at(context: &FileContext, line: usize) -> String {
    context
        .source
        .lines()
        .nth(line.saturating_sub(1))
        .map(|source_line| source_line.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::body_has_manual_guard;

    #[test]
    fn detects_assert_eq_guard() {
        let block: syn::Block = syn::parse_quote!({
            assert_eq!(env::predecessor_account_id(), env::current_account_id());
        });
        assert!(body_has_manual_guard(&block));
    }

    #[test]
    fn detects_branch_guard() {
        let block: syn::Block = syn::parse_quote!({
            if env::predecessor_account_id() != env::current_account_id() {
                env::panic_str("only self");
            }
        });
        assert!(body_has_manual_guard(&block));
    }

    #[test]
    fn detects_assert_self_macro() {
        let block: syn::Block = syn::parse_quote!({
            assert_self!();
        });
        assert!(body_has_manual_guard(&block));
    }

    #[test]
    fn ignores_partial_or_unrelated_bodies() {
        let partial: syn::Block = syn::parse_quote!({
            let caller = env::predecessor_account_id();
        });
        assert!(!body_has_manual_guard(&partial));

        let unrelated: syn::Block = syn::parse_quote!({
            env::log_str("done");
        });
        assert!(!body_has_manual_guard(&unrelated));
    }
}
