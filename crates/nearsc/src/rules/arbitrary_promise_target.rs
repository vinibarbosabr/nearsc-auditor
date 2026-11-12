//! NS010: cross-contract promise to a caller-chosen target.
//!
//! `Promise::new(account)` schedules actions on any NEAR account. When the
//! target comes from a method parameter (or a value derived from one), the
//! caller steers where the contract sends value and which contract receives
//! its calls. Combined with attached deposits or the contract's privileges,
//! this is a confused deputy.
//!
//! v0.1 scope (heuristic): flag `Promise::new(<expr>)` where the expression
//! is a method parameter (directly, or a `let` binding from one) and the
//! body has no allowlist check on it (a comparison/match against a literal,
//! a `contains`/`allowlist`/`allowed` mention, or an owner guard). String
//! literals and `env::current_account_id()` pass. Escrows and routers whose
//! whole purpose is paying caller-specified accounts remain heuristic
//! findings; the message asks for the allowlist evidence.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::common::body_token_text;
use super::{body_has_guard, last_segment_is, snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct ArbitraryPromiseTarget;

const RULE_ID: &str = "NS010";
const TITLE: &str = "Promise target chosen by the caller";
const REFS: &[&str] = &["https://docs.near.org/smart-contracts/anatomy/actions"];

/// Parameter names that carry the predecessor this same contract recorded
/// when the initiating method ran (`create` serializes it into the callback
/// args; the callback refunds it on failure). The name binding — not the
/// dataflow — is what distinguishes the refund path from a caller-chosen
/// target in the v0.1 heuristic.
const RECORDED_PREDECESSOR_PARAMS: &[&str] = &["predecessor_account_id"];

impl Rule for ArbitraryPromiseTarget {
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
                severity: Severity::High,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "public method `{}` builds a Promise::new target from caller input without an allowlist check; restrict targets to state-derived values or an allowlist before the contract pays or calls attacker-chosen accounts",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], sig: &syn::Signature, body: &syn::Block) {
        let params: Vec<String> = sig
            .inputs
            .iter()
            .filter_map(|arg| match arg {
                syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
                    syn::Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
                    syn::Pat::Path(pat_path) => pat_path
                        .path
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        if params.is_empty() {
            return;
        }
        let mut probe = PromiseProbe {
            params: params.clone(),
            first_target: None,
            first_target_param: None,
            recorded_aliases: Vec::new(),
        };
        probe.visit_block(body);
        let Some((line, column)) = probe.first_target else {
            return;
        };
        // Callback refund exemption: on a `#[private]` callback, a promise
        // target bound to the recorded-predecessor parameter (or one of its
        // aliases) is the refund path the contract built in the initiating
        // call, not a caller-chosen target (the sputnikdao-factory2
        // `on_create` shape).
        let is_callback = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        let is_recorded_predecessor = probe
            .first_target_param
            .as_deref()
            .is_some_and(|name| RECORDED_PREDECESSOR_PARAMS.contains(&name))
            || probe
                .first_target_param
                .is_some_and(|name| probe.recorded_aliases.contains(&name));
        if is_callback && is_recorded_predecessor {
            return;
        }
        // An allowlist mention or a full owner guard keeps the method off
        // this rule (heuristic release valve, same shape as NS002/NS012).
        let tokens = body_token_text(body);
        let allowlisted = tokens.contains("allowlist")
            || tokens.contains("allowed")
            || tokens.contains("contains");
        if allowlisted || body_has_guard(body) {
            return;
        }
        self.fns.push(FnInfo {
            name: ident.to_string(),
            line,
            column,
        });
    }
}

struct PromiseProbe {
    params: Vec<String>,
    first_target: Option<(usize, usize)>,
    /// Name of the parameter (or param alias) the first flagged target is
    /// bound to; consumed by the callback refund exemption.
    first_target_param: Option<String>,
    /// `let` aliases bound to a recorded-predecessor parameter.
    recorded_aliases: Vec<String>,
}

impl PromiseProbe {
    /// The parameter (or param alias) this expression resolves to, when it
    /// does. `let` bindings from parameters are tracked in `params` as the
    /// walk descends.
    fn param_name(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .filter(|name| self.params.contains(name)),
            Expr::Reference(reference) => self.param_name(&reference.expr),
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for PromiseProbe {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let is_promise_new = match &*call.func {
            Expr::Path(path) => {
                let names: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                names.len() == 2 && names[0] == "Promise" && names[1] == "new"
            }
            _ => false,
        };
        if is_promise_new && self.first_target.is_none() {
            if let Some(arg) = call.args.first() {
                if let Some(param) = self.param_name(arg) {
                    let start = call.func.span().start();
                    self.first_target = Some((start.line, start.column + 1));
                    self.first_target_param = Some(param);
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "new" && self.first_target.is_none() {
            // `Promise::new` surfaces as a method call only through macro
            // unexpanded paths; treat `Promise.new(x)` shape the same.
            let receiver_is_promise = match &*call.receiver {
                Expr::Path(path) => path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "Promise"),
                _ => false,
            };
            if receiver_is_promise {
                if let Some(arg) = call.args.first() {
                    if let Some(param) = self.param_name(arg) {
                        let start = call.method.span().start();
                        self.first_target = Some((start.line, start.column + 1));
                        self.first_target_param = Some(param);
                    }
                }
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        if let syn::Stmt::Local(local) = stmt {
            // Track `let alias = <param>;` so aliases stay flagged, and
            // remember the alias so the callback refund exemption can
            // resolve `Promise::new(alias)` back to the recorded predecessor
            // parameter.
            if let Some(init) = &local.init {
                if let Some(source) = self.param_name(&init.expr) {
                    let alias = match &local.pat {
                        syn::Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
                        syn::Pat::Path(pat_path) => pat_path
                            .path
                            .segments
                            .last()
                            .map(|segment| segment.ident.to_string()),
                        _ => None,
                    };
                    if let Some(alias) = alias {
                        if RECORDED_PREDECESSOR_PARAMS.contains(&source.as_str()) {
                            self.recorded_aliases.push(alias.clone());
                        }
                        self.params.push(alias);
                    }
                }
            }
        }
        syn::visit::visit_stmt(self, stmt);
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.sig, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(
            &item.sig.ident,
            &item.attrs,
            &item.sig,
            &item.block,
        );
        syn::visit::visit_impl_item_fn(self, item);
    }
}
