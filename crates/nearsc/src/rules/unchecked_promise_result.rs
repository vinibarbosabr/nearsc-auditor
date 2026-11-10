//! NS004: promise results consumed without a `Failed` arm.
//!
//! Cross-contract calls fail in practice. Callback code that consumes
//! `env::promise_result` (or names `PromiseResult`) without handling
//! `PromiseResult::Failed` updates state on a lie or bricks the flow.
//! `#[callback*]` deserialization is not flagged: the near-sdk macro unwraps
//! and panics by design, which is documented semantics.

use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::{snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct UncheckedPromiseResult;

const RULE_ID: &str = "NS004";
const TITLE: &str = "Promise result consumed without Failed handling";
const REFS: &[&str] = &["https://github.com/near/near-sdk-rs"];

impl Rule for UncheckedPromiseResult {
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
    /// The body consumes a promise result (calls `promise_result` or names
    /// `PromiseResult`).
    consumes_result: bool,
    /// The body matches an arm ending in `Failed`.
    handles_failed: bool,
    line: usize,
    column: usize,
}

impl Collector {
    fn into_findings(self, context: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for candidate in &self.fns {
            if candidate.consumes_result && !candidate.handles_failed {
                findings.push(Finding {
                    rule_id: RULE_ID,
                    title: TITLE,
                    severity: Severity::High,
                    confidence: Confidence::Heuristic,
                    file: context.file.clone(),
                    line: candidate.line,
                    column: candidate.column,
                    snippet: snippet_at(context, candidate.line),
                    message: format!(
                        "function `{}` consumes a promise result without matching PromiseResult::Failed; state can advance on a failed cross-contract call",
                        candidate.name
                    ),
                    refs: REFS,
                });
            }
        }
        findings
    }

    fn push_fn(&mut self, ident: &syn::Ident, body: &syn::Block) {
        let mut probe = PromiseProbe::default();
        probe.visit_block(body);
        self.fns.push(FnInfo {
            name: ident.to_string(),
            consumes_result: probe.consumes_result,
            handles_failed: probe.handles_failed,
            line: ident.span().start().line,
            column: ident.span().start().column + 1,
        });
    }
}

#[derive(Default)]
struct PromiseProbe {
    consumes_result: bool,
    handles_failed: bool,
}

impl<'ast> Visit<'ast> for PromiseProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "promise_result" {
            self.consumes_result = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                if segment.ident == "promise_result" {
                    self.consumes_result = true;
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(segment) = path.path.segments.last() {
            if segment.ident == "PromiseResult" {
                self.consumes_result = true;
            }
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_match(&mut self, expr: &'ast syn::ExprMatch) {
        // Any `Failed` pattern arm in the match counts as failure handling.
        for arm in &expr.arms {
            if arm_pat_is_failed(&arm.pat) {
                self.handles_failed = true;
            }
        }
        syn::visit::visit_expr_match(self, expr);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let Expr::Let(syn::ExprLet { pat, .. }) = expr {
            if arm_pat_is_failed(pat) {
                self.handles_failed = true;
            }
        }
        syn::visit::visit_expr(self, expr);
    }
}

/// Does a match/if-let pattern end in a `Failed` variant?
fn arm_pat_is_failed(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Failed"),
        syn::Pat::TupleStruct(tuple) => tuple
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Failed"),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.push_fn(&item.sig.ident, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(&item.sig.ident, &item.block);
        syn::visit::visit_impl_item_fn(self, item);
    }
}
