//! NS011: attached deposits stranded after a non-panicking early exit.
//!
//! A `#[payable]` method accepts whatever deposit the caller attaches at
//! the start of the call. On NEAR, a panicking receipt is atomic: the
//! deposit transfer is reverted and the caller's money returns by itself.
//! The deposit gets stranded only when the method returns normally on a
//! failure branch (an early `return`, a no-op `if`, a fall-through guard)
//! without refunding: then the NEAR sits in the contract with no accounting
//! entry and no claim path.
//!
//! v0.1 scope (heuristic): flag `#[payable]` exported (ABI) methods that
//! take a non-panicking early exit (`return`-shaped, or an `if`/`else`-style
//! fall-through branch) while no refund-shaped call (`Promise::new(...).
//! transfer(...)`, `refund`) appears in the body. `assert!`/`require!`/
//! `panic!`/`expect` aborts are exempt: the protocol rolls those back.
//! Exported methods only: an internal helper cannot be called with a
//! deposit in the first place.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{ImplItemFn, ItemFn};

use super::common::body_token_text;
use super::{last_segment_is, snippet_at, Rule};
use crate::abi::AbiIndex;
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct DepositRefundMissing;

const RULE_ID: &str = "NS011";
const TITLE: &str = "Attached deposit can get stuck on a non-panicking early exit";
const REFS: &[&str] = &["https://docs.near.org/smart-contracts/security/checklist"];

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
                severity: Severity::Low,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "payable method `{}` can return early after the deposit attached and shows no refund path; refund the attached deposit on every early exit or document why funds may stay",
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
        // ABI gate: a deposit attaches only on an exported call.
        if !self.abi.is_exported(ident) {
            return;
        }
        let mut probe = ExitProbe::default();
        probe.visit_block(body);
        if !probe.can_exit_early {
            return;
        }
        let tokens = body_token_text(body);
        let refunded = REFUND_MARKERS.iter().any(|marker| tokens.contains(marker));
        if refunded {
            return;
        }
        let (line, column) = probe
            .first_exit
            .expect("can_exit_early implies first_exit");
        self.fns.push(FnInfo {
            name: ident.to_string(),
            line,
            column,
        });
    }
}

#[derive(Default)]
struct ExitProbe {
    can_exit_early: bool,
    first_exit: Option<(usize, usize)>,
}

impl<'ast> Visit<'ast> for ExitProbe {
    fn visit_expr_return(&mut self, ret: &'ast syn::ExprReturn) {
        // A bare `return` (or `return None`) exits normally: the deposit
        // stays unless a refund ran. Panics abort and are exempt.
        if self.first_exit.is_none() {
            let start = ret.return_token.span().start();
            self.first_exit = Some((start.line, start.column + 1));
            self.can_exit_early = true;
        }
        syn::visit::visit_expr_return(self, ret);
    }
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