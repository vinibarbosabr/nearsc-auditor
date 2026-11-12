//! NS004: promise results consumed without a `Failed` arm.
//!
//! Cross-contract calls fail in practice. Callback code that consumes
//! `env::promise_result` (or names `PromiseResult`) without handling
//! `PromiseResult::Failed` updates state on a lie or bricks the flow.
//! `#[callback*]` deserialization is not flagged: the near-sdk macro unwraps
//! and panics by design, which is documented semantics.
//!
//! v0.1 scope: exported (ABI) functions only, plus any function that reads a
//! promise result — a `#[private]` callback IS the ABI surface for the
//! promise it resolves, so the ABI gate would be wrong here; internal
//! helpers that never touch promise results are not flagged either way.
//! Recognized failure handling: a `Failed`-named match/if-let arm, and a
//! `let ... else` binding on a `PromiseResult` whose else-branch aborts
//! (`panic!`/`panic_str`/`abort`): the abort means no state advances on a
//! failed call.

use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::snippet_at;
use super::Rule;
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
    /// The body matches an arm ending in `Failed`, or aborts in the
    /// else-branch of a `let ... else` on a `PromiseResult`.
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

    fn visit_local(&mut self, local: &'ast syn::Local) {
        // `let PAT = promise_result(...) else { panic }` is explicit failure
        // handling: the else-branch aborts, so no state advances on
        // `Failed`. Let-else lives on `Local` (syn keeps the else block on
        // `LocalInit.diverge`, not on `ExprLet`). Overriding `visit_local`
        // (not `visit_stmt`) is what makes this fire inside `if`/`else`
        // blocks too: `Stmt::Local` dispatches here from anywhere.
        self.check_let_else_local(local);
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_let(&mut self, expr: &'ast syn::ExprLet) {
        // let-else in expression position: `ExprLet` does not carry the
        // else block, so the abort cannot be verified here; the statement
        // form (`visit_local` above) does. This arm only records
        // consumption so expression-position lets do not go silent.
        if expr_names_promise_result(&expr.expr) {
            self.consumes_result = true;
        }
        syn::visit::visit_expr_let(self, expr);
    }
}

impl PromiseProbe {
    /// A `let PAT = promise_result(...) else { ... }` whose else-branch
    /// aborts counts as `Failed` handling. AST probe over the else block;
    /// `AbortProbe` covers `panic!`, `env::panic_str`, and abort calls.
    fn check_let_else_local(&mut self, local: &syn::Local) {
        let Some(init) = &local.init else {
            return;
        };
        let Some((_, diverge)) = &init.diverge else {
            return;
        };
        if !arm_pat_is_failed_or_any(&local.pat) || !expr_names_promise_result(&init.expr) {
            return;
        }
        let mut probe = AbortProbe::default();
        match &**diverge {
            Expr::Block(block) => probe.visit_block(&block.block),
            other => probe.visit_expr(other),
        }
        if probe.aborts {
            self.handles_failed = true;
        }
    }
}

/// Does a match/if-let pattern end in the `Failed` variant?
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

/// Does a `let ... else` pattern name a `PromiseResult` variant at all?
/// (Any variant: the else-branch runs for every other outcome, and below we
/// require that branch to abort.)
fn arm_pat_is_failed_or_any(pat: &syn::Pat) -> bool {
    matches!(
        pat,
        syn::Pat::Path(_) | syn::Pat::TupleStruct(_) | syn::Pat::Struct(_)
    )
}

/// Is the scrutinee a promise-result expression (`env::promise_result(0)` or
/// any nested spelling of it)?
fn expr_names_promise_result(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => {
            let names_promise_call = matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|s| s.ident == "promise_result"));
            names_promise_call
                || call.args.iter().any(expr_names_promise_result)
                || expr_calls_promise_result_method(call)
        }
        Expr::MethodCall(call) => {
            call.method == "promise_result" || expr_names_promise_result(&call.receiver)
        }
        _ => false,
    }
}

/// `promise_result(0)` parsed as a call whose func path ends in the method
/// name (the plain, unqualified spelling).
fn expr_calls_promise_result_method(call: &syn::ExprCall) -> bool {
    match &*call.func {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "promise_result"),
        _ => false,
    }
}

#[derive(Default)]
struct AbortProbe {
    aborts: bool,
}

impl<'ast> Visit<'ast> for AbortProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        // `env::panic_str("...")` / `env::panic("...")`
        if call.method == "panic_str" || call.method == "panic" {
            self.aborts = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        // `env::panic_str("...")` parses as a CALL whose func path ends in
        // `panic_str`; `std::process::abort()` and `panic(...)`.
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                if segment.ident == "abort" || segment.ident == "panic_str" || segment.ident == "panic" {
                    self.aborts = true;
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
            .is_some_and(|segment| segment.ident == "panic")
        {
            self.aborts = true;
        }
        syn::visit::visit_macro(self, mac);
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

#[cfg(test)]
mod tests {
    use super::PromiseProbe;
    use syn::visit::Visit;

    /// The sputnik `update` shape: a let-else on `env::promise_result(0)`
    /// whose else-branch panics, nested inside an `if/else`. The probe
    /// must credit it as `Failed` handling.
    #[test]
    fn let_else_with_abort_counts_as_failed_handling() {
        let body: syn::Block = syn::parse_quote!({
            let new_contract_code = if is_callback {
                #[allow(deprecated)]
                let PromiseResult::Successful(data) = env::promise_result(0) else {
                    env::panic_str("ERR_NO_RESULT");
                };
                data
            } else {
                env::input().expect("ERR_NO_INPUT")
            };
        });
        let mut probe = PromiseProbe::default();
        probe.visit_block(&body);
        assert!(probe.consumes_result);
        assert!(probe.handles_failed, "let-else abort must count");
    }

    /// A let-else that does NOT abort (falls through) is not failure
    /// handling: state could still advance on `Failed`.
    #[test]
    fn let_else_without_abort_is_not_failed_handling() {
        let body: syn::Block = syn::parse_quote!({
            let PromiseResult::Successful(data) = env::promise_result(0) else {
                data = vec![];
            };
        });
        let mut probe = PromiseProbe::default();
        probe.visit_block(&body);
        assert!(probe.consumes_result);
        assert!(!probe.handles_failed, "non-aborting else must not count");
    }
}
