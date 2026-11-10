//! NS003: panic-capable expressions inside `#[private]` callbacks.
//!
//! A panic in a callback aborts the receipt: state can stay half-updated and
//! retries are not automatic. Callbacks should handle failure explicitly, so
//! `unwrap`/`expect`/`panic!`/slice indexing inside a private callback is
//! flagged for review. Non-private callbacks are NS002's target.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Expr, ImplItemFn, ItemFn};

use super::{last_segment_is, snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct CallbackPanic;

const RULE_ID: &str = "NS003";
const TITLE: &str = "Callback can panic on failure";
const REFS: &[&str] = &["https://github.com/near/near-sdk-rs"];

/// Attributes that mark a function as a cross-contract callback.
const CALLBACK_ATTRS: &[&str] = &[
    "callback",
    "callback_result",
    "callback_unwrap",
    "callback_vec",
];

impl Rule for CallbackPanic {
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
    /// Names passed to `.then(...)` in this file.
    then_callbacks: Vec<String>,
    /// `#[private]` callback candidates.
    candidates: Vec<FnInfo>,
}

struct FnInfo {
    name: String,
    is_callback_attr: bool,
    panic_at: Option<(usize, usize)>,
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
            if !used_as_callback {
                continue;
            }
            if let Some((line, column)) = candidate.panic_at {
                findings.push(Finding {
                    rule_id: RULE_ID,
                    title: TITLE,
                    severity: Severity::Medium,
                    confidence: Confidence::Heuristic,
                    file: context.file.clone(),
                    line,
                    column,
                    snippet: snippet_at(context, line),
                    message: format!(
                        "callback `{}` can panic on attacker-influenced input; handle failure explicitly instead of unwrap/expect/indexing",
                        candidate.name
                    ),
                    refs: REFS,
                });
            }
        }
        findings
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[Attribute], body: &syn::Block) {
        let has_private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        if !has_private {
            return;
        }
        let mut probe = PanicProbe::default();
        probe.visit_block(body);
        self.candidates.push(FnInfo {
            name: ident.to_string(),
            is_callback_attr: CALLBACK_ATTRS
                .iter()
                .any(|name| attrs.iter().any(|attr| last_segment_is(attr, name))),
            panic_at: probe.first,
        });
    }
}

#[derive(Default)]
struct PanicProbe {
    first: Option<(usize, usize)>,
}

impl<'ast> Visit<'ast> for PanicProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.first.is_none() && (call.method == "unwrap" || call.method == "expect") {
            let start = call.method.span().start();
            self.first = Some((start.line, start.column + 1));
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_index(&mut self, index: &'ast syn::ExprIndex) {
        if self.first.is_none() {
            let start = index.expr.span().start();
            self.first = Some((start.line, start.column + 1));
        }
        syn::visit::visit_expr_index(self, index);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if self.first.is_none() {
            if let Some(segment) = mac.path.segments.last() {
                if segment.ident == "panic" {
                    let start = mac.path.segments.last().unwrap().ident.span().start();
                    self.first = Some((start.line, start.column + 1));
                }
            }
        }
        syn::visit::visit_macro(self, mac);
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

/// Extract the callback function name from the argument to `.then(...)`.
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
