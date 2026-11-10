//! NS012: privileged setter reachable without an access-control guard.
//!
//! Public methods named `set_*`, `update_*`, `pause_*`, `unpause_*`,
//! `withdraw_*`, or `admin_*` change contract configuration or move funds.
//! NEAR has implicit authorization: without `#[private]` or a
//! predecessor/owner check, any account can call them. The naming convention
//! reveals intent; a setter without a guard is a bug or a missing attribute
//! either way, so the rule flags both for review.

use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::{body_has_guard, last_segment_is, snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct PrivilegedSetter;

const RULE_ID: &str = "NS012";
const TITLE: &str = "Privileged setter without a guard";
const REFS: &[&str] = &["https://docs.near.org/protocol/accounts-contracts/access-keys.md"];

/// Name prefixes that signal privileged configuration or fund movement.
const SETTER_PREFIXES: &[&str] = &[
    "set_",
    "update_",
    "pause_",
    "unpause_",
    "withdraw_",
    "admin_",
];

impl Rule for PrivilegedSetter {
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
    fns: Vec<FnInfo>,
}

struct FnInfo {
    name: String,
    line: usize,
    column: usize,
}

impl Collector {
    fn into_findings(self, context: &FileContext) -> Vec<Finding> {
        self.fns
            .into_iter()
            .map(|candidate| Finding {
                rule_id: RULE_ID,
                title: TITLE,
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "public setter `{}` changes privileged state or moves funds without a guard; restrict it with #[private] or assert predecessor == owner/current_account_id",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], body: &syn::Block) {
        let name = ident.to_string();
        let privileged_name = SETTER_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));
        if !privileged_name {
            return;
        }
        let private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        if private || body_has_guard(body) {
            return;
        }
        // Direct state writes fall under NS006 (critical, whole-function
        // verdict). Reporting the same function here too would double-count a
        // single access-control bug, so NS012 skips those bodies and stays the
        // config/privilege-election reviewer.
        if body_writes_state(body) {
            return;
        }
        let start = ident.span().start();
        self.fns.push(FnInfo {
            name,
            line: start.line,
            column: start.column + 1,
        });
    }
}

/// Does the body call `state_write` (directly or inside a macro)? Shared
/// verdict shape with NS006: a direct write is that rule's finding, NS012
/// defers to it to keep one access-control bug on one rule.
fn body_writes_state(block: &syn::Block) -> bool {
    #[derive(Default)]
    struct WriteProbe {
        writes: bool,
    }

    impl<'ast> Visit<'ast> for WriteProbe {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "state_write" {
                self.writes = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                if let Some(segment) = path.path.segments.last() {
                    if segment.ident == "state_write" {
                        self.writes = true;
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
                .is_some_and(|segment| segment.ident == "state_write")
            {
                self.writes = true;
            }
            if mac.tokens.to_string().contains("state_write") {
                self.writes = true;
            }
            syn::visit::visit_macro(self, mac);
        }
    }

    let mut probe = WriteProbe::default();
    probe.visit_block(block);
    probe.writes
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_impl_item_fn(self, item);
    }
}
