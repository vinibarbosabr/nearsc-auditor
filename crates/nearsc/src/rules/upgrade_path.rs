//! NS006: `state_write` reachable from an unguarded public function.
//!
//! Direct state writes bypass the storage model and are the final step of an
//! upgrade. If a caller reaches one without `#[private]` or an explicit
//! predecessor assertion, they own the contract. v0.1 flags direct
//! `state_write` call sites only; migrate-deserialization reachability lands
//! with dataflow analysis in v0.2.

use syn::visit::Visit;
use syn::{ImplItemFn, ItemFn};

use super::{body_has_guard, last_segment_is, snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct UpgradePath;

const RULE_ID: &str = "NS006";
const TITLE: &str = "Unguarded state write reachable from a public function";
const REFS: &[&str] = &["https://github.com/near/near-sdk-rs"];

impl Rule for UpgradePath {
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
                severity: Severity::Critical,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "function `{}` writes contract state without an access-control guard; a caller can overwrite it. Add #[private] or assert predecessor == current_account_id / owner",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], body: &syn::Block) {
        let has_private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        if has_private || body_has_guard(body) {
            return;
        }
        let writes_state = body_writes_state(body);
        if !writes_state {
            return;
        }
        let start = ident.span().start();
        self.fns.push(FnInfo {
            name: ident.to_string(),
            line: start.line,
            column: start.column + 1,
        });
    }
}

/// Does the body call `state_write` (e.g. `env::state_write(...)`), directly
/// or inside a macro?
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
            if let syn::Expr::Path(path) = &*call.func {
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
