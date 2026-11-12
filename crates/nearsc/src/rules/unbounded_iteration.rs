//! NS007: unbounded iteration over user-growable collections in public
//! methods.
//!
//! NEAR gas is capped per receipt. A public method that loops over a
//! collection which users can grow eventually becomes uncallable: the loop
//! itself exhausts the gas, locking whatever the method guards (funds,
//! governance, migrations). Pagination or a bounded window is the fix.
//!
//! v0.1 scope: exported (ABI) functions only — `pub` methods of `#[near]`
//! impl blocks and raw `#[no_mangle]` exports. Internal helpers loop only
//! where their exported callers let them, so they are the v0.2 call graph's
//! targets.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::{last_segment_is, snippet_at, Rule};
use crate::abi::AbiIndex;
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct UnboundedIteration;

const RULE_ID: &str = "NS007";
const TITLE: &str = "Unbounded loop over a user-growable collection";
const REFS: &[&str] = &["https://docs.near.org/smart-contracts/anatomy/optimizations"];

/// Iteration methods that hand out a collection's contents.
const ITERATION_METHODS: &[&str] = &["iter", "into_iter", "keys", "values", "iter_from", "drain"];

impl Rule for UnboundedIteration {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn check(&self, context: &FileContext) -> Vec<Finding> {
        let mut collector = Collector {
            abi: &context.abi,
            fns: Vec::new(),
        };
        collector.visit_file(&context.ast);
        collector.into_findings(context)
    }
}

struct Collector<'a> {
    abi: &'a AbiIndex,
    fns: Vec<FnInfo>,
}

struct FnInfo {
    name: String,
    line: usize,
    column: usize,
}

impl Collector<'_> {
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
                    "public method `{}` loops over a collection that callers can grow without a bound; add pagination or cap the iteration before gas makes this method uncallable",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], body: &syn::Block) {
        // ABI gate: only an exported `pub` method (or a raw `#[no_mangle]`
        // export) is callable by an arbitrary account.
        if !self.abi.is_exported(ident) {
            return;
        }
        let private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        let init = attrs.iter().any(|attr| last_segment_is(attr, "init"));
        if private || init {
            return;
        }
        let mut probe = LoopProbe::default();
        probe.visit_block(body);
        if let Some((line, column)) = probe.first_unbounded {
            self.fns.push(FnInfo {
                name: ident.to_string(),
                line,
                column,
            });
        }
    }
}

#[derive(Default)]
struct LoopProbe {
    first_unbounded: Option<(usize, usize)>,
}

impl<'ast> Visit<'ast> for LoopProbe {
    fn visit_expr_for_loop(&mut self, loop_expr: &'ast syn::ExprForLoop) {
        if self.first_unbounded.is_none() && is_self_collection_iterable(&loop_expr.expr) {
            let start = loop_expr.for_token.span().start();
            self.first_unbounded = Some((start.line, start.column + 1));
        }
        syn::visit::visit_expr_for_loop(self, loop_expr);
    }
}

/// Is this expression iterating a `self.`-rooted collection (the field
/// directly, a borrow of it, or a chain through iteration methods)?
fn is_self_collection_iterable(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(call) => {
            is_self_collection_iterable(&call.receiver) && is_iteration_method(&call.method)
        }
        Expr::Reference(reference) => is_self_collection_iterable(&reference.expr),
        Expr::Field(field) => is_self_field(&field.base),
        Expr::Index(index) => is_self_collection_iterable(&index.expr),
        _ => false,
    }
}

/// `self`, `self.field`, `self.inner.field`: any chain rooted at `self`.
fn is_self_field(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path.path.segments.len() == 1 && path.path.segments[0].ident == "self",
        Expr::Field(field) => is_self_field(&field.base),
        _ => false,
    }
}

fn is_iteration_method(method: &syn::Ident) -> bool {
    ITERATION_METHODS.contains(&method.to_string().as_str())
}

impl<'ast> Visit<'ast> for Collector<'ast> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_impl_item_fn(self, item);
    }
}
