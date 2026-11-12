//! NS013: repeatable balance drain — transfer without a state decrement.
//!
//! A method that pays out an amount derived from recorded contract state
//! (a per-user balance, a ledger credit) must reduce the state it draws
//! from in the same method. When it does not, the payout is repeatable:
//! the same credit can be withdrawn on every call until the contract's
//! NEAR balance is exhausted, and any later accounting that refunds the
//! recorded balance pays it a second time.
//!
//! Real-world precedent: sputnik-dao-contract issue #239 —
//! `storage_withdraw` computes `available` from `user.near_amount -
//! user.storage_used`, transfers it, and never decrements
//! `user.near_amount`; every call can re-drain the credit.
//!
//! v0.1 scope (heuristic): flag exported methods whose body both
//! (a) builds a `Promise::new(...).transfer(...)` payout, and (b) mentions
//! a balance-shaped amount that reads recorded state (`*_available`,
//! `*_balance`, `*_amount`, ...), when the body performs no state
//! mutation of the recorded fields (`insert`/`set`/`save`/`remove`/
//! subtraction on `self` state). The ABI gate and the method-name channel
//! (`storage_withdraw` is a NEP-145 endpoint) keep the surface honest;
//! the heuristic is a review hint, not a verdict.

use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::common::body_writes_state;
use super::storage_griefing;
use super::{snippet_at, Rule};
use crate::abi::AbiIndex;
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct BalanceDrainTransfer;

const RULE_ID: &str = "NS013";
const TITLE: &str = "Repeatable balance drain (payout without a state decrement)";
const REFS: &[&str] = &["https://github.com/near-daos/sputnik-dao-contract/issues/239"];

/// NEP-145/ledger endpoint names where the repeatable-drain class appears.
const PAYOUT_ENDPOINT_NAMES: &[&str] = &["storage_withdraw", "withdraw"];

/// Amount readouts that derive a payout from recorded state.
const BALANCE_READOUTS: &[&str] = &[
    "storage_available",
    "available",
    "balance_of",
    "get_balance",
    "near_amount",
];

/// State mutations that reduce (or re-book) the recorded balance: collection
/// writes and subtraction assignments. Their presence means the payout
/// draws down the ledger in the same method.
const DECREMENT_MARKERS: &[&str] = &[
    "insert",
    "save_user",
    "remove",
    "unregister",
    "swap_remove",
    "set",
];

impl Rule for BalanceDrainTransfer {
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
                severity: Severity::High,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "method `{}` pays out an amount derived from recorded state without reducing the state it draws from; the same credit can be withdrawn again on every call (see issue #239 for the damage pattern)",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], body: &syn::Block) {
        let name = ident.to_string();
        // Payout endpoints only: the drain class needs a caller-facing
        // payout path; internal helpers are reached through one anyway.
        if !PAYOUT_ENDPOINT_NAMES.contains(&name.as_str()) {
            return;
        }
        // ABI gate: an internal helper is not itself an endpoint.
        if !self.abi.is_exported(ident) {
            return;
        }
        let private = attrs
            .iter()
            .any(|attr| super::last_segment_is(attr, "private"));
        if private {
            return;
        }
        let mut probe = DrainProbe::default();
        probe.visit_block(body);
        if !probe.transfers || !probe.reads_balance {
            return;
        }
        // A direct self-collection write in this body means the ledger is
        // re-booked here (the fixed shape). Note: `save_user(&sender_id,
        // sender)` style decrements run through helpers, which the token
        // markers below catch instead.
        if body_writes_state(body) {
            return;
        }
        let tokens = body_tokens(body);
        if DECREMENT_MARKERS
            .iter()
            .any(|marker| tokens.iter().any(|tn| tn == marker))
        {
            return;
        }
        // A subtraction assignment on a self field (`self.near_amount -= x`,
        // `self.ledger.insert(...)`) draws down the recorded balance.
        if probe.self_field_subtraction {
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

#[derive(Default)]
struct DrainProbe {
    transfers: bool,
    reads_balance: bool,
    self_field_subtraction: bool,
}

impl<'ast> Visit<'ast> for DrainProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "transfer" {
            // `Promise::new(...).transfer(...)` — a NEAR payout.
            self.transfers = true;
        }
        if BALANCE_READOUTS.contains(&call.method.to_string().as_str()) {
            self.reads_balance = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, expr: &'ast syn::ExprBinary) {
        // `self.field -= x` / `self.field = self.field - x`: a decrement of
        // recorded state in this body.
        if matches!(
            expr.op,
            syn::BinOp::SubAssign(_) | syn::BinOp::Sub(_) | syn::BinOp::RemAssign(_)
        ) {
            let mut probe = SelfFieldProbe::default();
            probe.visit_expr(&expr.left);
            if probe.mentions_self_field {
                self.self_field_subtraction = true;
            }
        }
        syn::visit::visit_expr_binary(self, expr);
    }
}

#[derive(Default)]
struct SelfFieldProbe {
    mentions_self_field: bool,
}

impl<'ast> Visit<'ast> for SelfFieldProbe {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if matches!(&*field.base, Expr::Path(path) if path.path.segments.len() == 1 && path.path.segments[0].ident == "self")
        {
            self.mentions_self_field = true;
        }
        syn::visit::visit_expr_field(self, field);
    }
}

/// All identifier spellings in the body, flattened through macro groups.
/// Shared implementation lives in `storage_griefing::body_tokens`.
fn body_tokens(block: &syn::Block) -> Vec<String> {
    storage_griefing::body_tokens(block)
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(&item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_impl_item_fn(self, item);
    }
}
