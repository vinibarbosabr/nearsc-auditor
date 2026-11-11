//! NS011: attached deposits that can get stuck after a failed validation.
//!
//! A `#[payable]` method accepts whatever deposit the caller attaches at
//! the start of the call. If the method then fails an assertion after doing
//! meaningful work, and the body has no refund path
//! (`Promise::new(predecessor).transfer(...)`, `refund`, `PromiseOrValue`
//! handling), the attached deposit stays in the contract: NEAR does not
//! roll back transfers into the account on assert failures.
//!
//! v0.1 scope (heuristic): flag `#[payable]` methods whose body contains an
//! `assert!`/`require!`/`assert_eq!`/`panic`-shaped early exit while no
//! refund-shaped call appears in the body. The heuristic assumes an
//! assert-then-fail can happen after the deposit has attached; the message
//! asks for the refund path explicitly.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::common::body_token_text;
use super::{last_segment_is, snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct DepositRefundMissing;

const RULE_ID: &str = "NS011";
const TITLE: &str = "Attached deposit can get stuck on a failed validation";
const REFS: &[&str] = &["https://docs.near.org/smart-contracts/anatomy/actions"];

/// Macros/methods that can abort the call after the deposit attached.
const ABORT_SHAPES: &[&str] = &["assert", "require", "panic", "assert_eq", "assert_ne"];

/// Body mentions that satisfy "the caller gets their money back".
///
/// `attached_deposit` is deliberately NOT in this list: reading the deposit
/// amount is not a refund. Fixtures that assert on the deposit need a real
/// refund path (transfer/refund) to pass.
const REFUND_MARKERS: &[&str] = &["refund", "transfer"];

impl Rule for DepositRefundMissing {
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
                severity: Severity::Low,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "payable method `{}` can abort after the deposit attached and shows no refund path; refund the attached deposit on every early exit or document why funds may stay",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], body: &syn::Block) {
        let payable = attrs.iter().any(|attr| last_segment_is(attr, "payable"));
        if !payable {
            return;
        }
        let mut probe = AbortProbe::default();
        probe.visit_block(body);
        if !probe.can_abort {
            return;
        }
        let tokens = body_token_text(body);
        let refunded = REFUND_MARKERS.iter().any(|marker| tokens.contains(marker));
        if refunded {
            return;
        }
        let (line, column) = probe.first_abort.expect("can_abort implies first_abort");
        self.fns.push(FnInfo {
            name: ident.to_string(),
            line,
            column,
        });
    }
}

#[derive(Default)]
struct AbortProbe {
    can_abort: bool,
    first_abort: Option<(usize, usize)>,
}

impl<'ast> Visit<'ast> for AbortProbe {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        if ABORT_SHAPES.contains(&name.as_str()) && self.first_abort.is_none() {
            let start = mac.path.span().start();
            self.first_abort = Some((start.line, start.column + 1));
            self.can_abort = true;
            return;
        }
        // Abort checks wrapped in other macros (assert!(cond), require!()
        // chains) still abort: scan the inner tokens for the same shapes.
        if !self.can_abort {
            let inner = mac.tokens.to_string();
            let mentions_abort = ABORT_SHAPES.iter().any(|shape| inner.contains(shape))
                || inner.contains("attached_deposit");
            if mentions_abort {
                let start = mac.path.span().start();
                self.first_abort = Some((start.line, start.column + 1));
                self.can_abort = true;
            }
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        if (name == "expect" || name == "panic") && self.first_abort.is_none() {
            let start = call.method.span().start();
            self.first_abort = Some((start.line, start.column + 1));
            self.can_abort = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                let name = segment.ident.to_string();
                if ABORT_SHAPES.contains(&name.as_str()) && self.first_abort.is_none() {
                    let start = segment.ident.span().start();
                    self.first_abort = Some((start.line, start.column + 1));
                    self.can_abort = true;
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
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
