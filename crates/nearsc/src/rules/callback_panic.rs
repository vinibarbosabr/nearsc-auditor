//! NS003: panic-capable expressions inside `#[private]` callbacks.
//!
//! A panic in a callback aborts the receipt: state can stay half-updated and
//! retries are not automatic. Callbacks should handle failure explicitly, so
//! `unwrap`/`expect`/`panic!`/slice indexing inside a private callback is
//! flagged for review. Non-private callbacks are NS002's target.
//!
//! v0.2.0 campaign exemptions (issue #83, PotLock/near-sdk evidence):
//! - **Branch-first results.** `V.unwrap()` is exempt when the same function
//!   first proves `V` with a diverging `if V.is_err() { panic/return }`
//!   (the unwrap then runs only in the Ok case), when the unwrap sits in
//!   the `else` branch of an `if V.is_err()` (any then-branch shape), or
//!   when it is short-circuited behind `V.is_err() || ...` (`||` evaluates
//!   left first, so the unwrap only runs when `V` is Ok).
//! - **Loop-bound indexing.** `coll[idx]` is exempt when `idx` is the
//!   loop variable of `for idx in 0..coll.len()`.
//!
//! Both exemptions are pure AST facts: remove the branch or the bound and
//! the site is flagged again.

use std::collections::HashMap;
use std::collections::HashSet;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, Expr, ImplItemFn, ItemFn};

use super::common::callback_name;
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

    fn push_fn(
        &mut self,
        ident: &syn::Ident,
        sig: &syn::Signature,
        attrs: &[Attribute],
        body: &syn::Block,
    ) {
        let has_private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        if !has_private {
            return;
        }
        let params: Vec<String> = sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
                    syn::Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let mut walk = BodyWalk::new(&params);
        walk.visit_block(body);
        self.candidates.push(FnInfo {
            name: ident.to_string(),
            is_callback_attr: CALLBACK_ATTRS
                .iter()
                .any(|name| attrs.iter().any(|attr| last_segment_is(attr, name))),
            panic_at: walk.first_panic_site(),
        });
    }
}

/// One walk of one callback body, tracking branch-guarded result variables
/// and loop-bound indices, recording the first non-exempt panic site.
struct BodyWalk {
    /// Result variables guarded by a diverging `if V.is_err()` earlier in
    /// the current statement flow (plus the `else` branch of the guard
    /// itself, even when the then-branch only logs).
    guarded: HashSet<String>,
    /// `loop var -> collection` from `for idx in 0..coll.len()`.
    loop_bounds: HashMap<String, String>,
    /// First non-exempt panic-capable site (line, column).
    first: Option<(usize, usize)>,
}

impl BodyWalk {
    fn new(_params: &[String]) -> Self {
        // Params are not pre-guarded; only in-body branch guards credit.
        BodyWalk {
            guarded: HashSet::new(),
            loop_bounds: HashMap::new(),
            first: None,
        }
    }

    fn record(&mut self, span_start: (usize, usize)) {
        if self.first.is_none() {
            self.first = Some(span_start);
        }
    }

    fn first_panic_site(&self) -> Option<(usize, usize)> {
        self.first
    }

    /// `Some(var)` when the whole expression is `V.is_err()`.
    fn cond_err_var(expr: &Expr) -> Option<String> {
        if let Expr::MethodCall(call) = expr {
            if call.method == "is_err" {
                if let Expr::Path(path) = &*call.receiver {
                    if path.path.segments.len() == 1 {
                        return Some(path.path.segments[0].ident.to_string());
                    }
                }
            }
        }
        None
    }

    /// Does the block diverge: any `return`, or a call/macro whose path ends
    /// in a `panic*` name (`env::panic_str`, `panic!`, ...), at any depth?
    fn diverges(stmts: &[syn::Stmt]) -> bool {
        #[derive(Default)]
        struct DivergenceProbe {
            diverges: bool,
        }

        impl<'ast> Visit<'ast> for DivergenceProbe {
            fn visit_expr_return(&mut self, expr: &'ast syn::ExprReturn) {
                self.diverges = true;
                syn::visit::visit_expr_return(self, expr);
            }

            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let Expr::Path(path) = &*call.func {
                    if path
                        .path
                        .segments
                        .last()
                        .is_some_and(|segment| segment.ident.to_string().starts_with("panic"))
                    {
                        self.diverges = true;
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }

            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if call.method.to_string().starts_with("panic") {
                    self.diverges = true;
                }
                syn::visit::visit_expr_method_call(self, call);
            }

            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                if mac
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident.to_string().starts_with("panic"))
                {
                    self.diverges = true;
                }
                syn::visit::visit_macro(self, mac);
            }
        }

        let mut probe = DivergenceProbe::default();
        for stmt in stmts {
            probe.visit_stmt(stmt);
        }
        probe.diverges
    }

    /// Collect `for idx in 0..coll.len()` loop bounds from a body.
    fn collect_loop_bounds(&mut self, block: &syn::Block) {
        struct LoopProbe<'a> {
            walk: &'a mut BodyWalk,
        }

        impl<'ast, 'a> Visit<'ast> for LoopProbe<'a> {
            fn visit_expr_for_loop(&mut self, loop_expr: &'ast syn::ExprForLoop) {
                let pat_ident = match &*loop_expr.pat {
                    syn::Pat::Ident(pat_ident) => pat_ident.ident.to_string(),
                    _ => String::new(),
                };
                if !pat_ident.is_empty() {
                    if let Expr::Range(range) = &*loop_expr.expr {
                        let from_zero = range.start.as_ref().is_some_and(|start| {
                            matches!(
                                &**start,
                                Expr::Lit(lit) if matches!(&lit.lit, syn::Lit::Int(i) if i.base10_digits() == "0")
                            )
                        });
                        if from_zero || range.start.is_none() {
                            if let Some(to) = &range.end {
                                if let Expr::MethodCall(call) = &**to {
                                    if call.method == "len" {
                                        if let Expr::Path(path) = &*call.receiver {
                                            if path.path.segments.len() == 1 {
                                                self.walk.loop_bounds.insert(
                                                    pat_ident,
                                                    path.path.segments[0].ident.to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                syn::visit::visit_expr_for_loop(self, loop_expr);
            }
        }

        let mut probe = LoopProbe { walk: self };
        probe.visit_block(block);
    }

    fn handle_if(&mut self, if_expr: &syn::ExprIf) {
        if let Some(var) = Self::cond_err_var(&if_expr.cond) {
            let then_diverges = Self::diverges(&if_expr.then_branch.stmts);
            // Then branch: current guarded set (no new credit from a guard
            // that is about to be proven - sites inside stay judged).
            for stmt in &if_expr.then_branch.stmts {
                self.visit_stmt(stmt);
            }
            // Else branch (including `else if`): the condition proved `V`
            // is Ok here, so unwraps in the else are exempt regardless of
            // what the then branch does.
            self.guarded.insert(var.clone());
            if let Some((_, else_expr)) = &if_expr.else_branch {
                self.visit_expr(else_expr);
            }
            // After the statement: only a diverging then branch makes the
            // rest of the block unreachable in the Err case.
            if then_diverges {
                self.guarded.insert(var);
            } else {
                self.guarded.remove(&var);
            }
            return;
        }
        // Not a result guard: plain walk, order preserved.
        self.visit_expr(&if_expr.cond);
        for stmt in &if_expr.then_branch.stmts {
            self.visit_stmt(stmt);
        }
        if let Some((_, else_expr)) = &if_expr.else_branch {
            self.visit_expr(else_expr);
        }
    }
}

impl<'ast> Visit<'ast> for BodyWalk {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        if self.loop_bounds.is_empty() {
            self.collect_loop_bounds(block);
        }
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        match stmt {
            syn::Stmt::Expr(Expr::If(if_expr), ..) => self.handle_if(if_expr),
            _ => syn::visit::visit_stmt(self, stmt),
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "unwrap" || call.method == "expect" {
            if let Expr::Path(path) = &*call.receiver {
                if path.path.segments.len() == 1 {
                    let var = path.path.segments[0].ident.to_string();
                    if !self.guarded.contains(&var) {
                        let start = call.method.span().start();
                        self.record((start.line, start.column + 1));
                    }
                } else {
                    // A guarded name behind a longer path is not the guarded
                    // local; conservative: record.
                    let start = call.method.span().start();
                    self.record((start.line, start.column + 1));
                }
            } else {
                // Receiver is a call chain (`self.x.pop().unwrap()`): no
                // variable to prove, always recorded.
                let start = call.method.span().start();
                self.record((start.line, start.column + 1));
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_index(&mut self, index: &'ast syn::ExprIndex) {
        // Loop-bound exemption: `coll[idx]` where `idx` is the loop variable
        // of `for idx in 0..coll.len()` and `coll` matches.
        let base = match &*index.expr {
            Expr::Path(path) if path.path.segments.len() == 1 => {
                path.path.segments[0].ident.to_string()
            }
            _ => String::new(),
        };
        let idx = match &*index.index {
            Expr::Path(path) if path.path.segments.len() == 1 => {
                path.path.segments[0].ident.to_string()
            }
            _ => String::new(),
        };
        let exempt =
            !base.is_empty() && !idx.is_empty() && self.loop_bounds.get(&idx) == Some(&base);
        if !exempt {
            let start = index.expr.span().start();
            self.record((start.line, start.column + 1));
        }
        syn::visit::visit_expr_index(self, index);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "panic")
        {
            let start = mac.path.segments.last().unwrap().ident.span().start();
            self.record((start.line, start.column + 1));
        }
        syn::visit::visit_macro(self, mac);
    }

    fn visit_expr_binary(&mut self, bin: &'ast syn::ExprBinary) {
        if matches!(bin.op, syn::BinOp::Or(_)) {
            // Short-circuit exemption: `V.is_err() || expr_with_V.unwrap()`.
            let mut operands = Vec::new();
            flatten_or(&bin.left, &mut operands);
            operands.push(&bin.right);
            let mut err_vars = Vec::new();
            for operand in &operands {
                if let Some(var) = Self::cond_err_var(operand) {
                    err_vars.push(var);
                }
            }
            if !err_vars.is_empty() {
                for var in &err_vars {
                    self.guarded.insert(var.clone());
                }
                for operand in &operands {
                    self.visit_expr(operand);
                }
                for var in &err_vars {
                    self.guarded.remove(var);
                }
                return;
            }
        }
        syn::visit::visit_expr_binary(self, bin);
    }
}

/// Flatten `a || b || c` into operand expressions (left-assoc chains).
fn flatten_or<'a>(expr: &'a syn::Expr, out: &mut Vec<&'a Expr>) {
    let expr: &'a Expr = match expr {
        Expr::Binary(bin) if matches!(bin.op, syn::BinOp::Or(_)) => {
            flatten_or(&bin.left, out);
            &bin.right
        }
        other => other,
    };
    out.push(expr);
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
        self.push_fn(&item.sig.ident, &item.sig, &item.attrs, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(&item.sig.ident, &item.sig, &item.attrs, &item.block);
        syn::visit::visit_impl_item_fn(self, item);
    }
}
