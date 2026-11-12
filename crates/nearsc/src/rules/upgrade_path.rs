//! NS006: `state_write` reachable from an unguarded public function.
//!
//! Direct state writes bypass the storage model and are the final step of an
//! upgrade. If a caller reaches one without `#[private]` or an explicit
//! predecessor assertion, they own the contract. v0.1 flags direct
//! `state_write` call sites in *exported* (ABI) functions only; internal
//! helpers and migrate-deserialization reachability land with dataflow
//! analysis in v0.2.
//!
//! Exemptions: `#[private]`, a manual predecessor/current-account or
//! owner-field guard, and deposit-funded writes (the caller pays the storage
//! cost of the state they cause, `store_blob`-style).

use syn::visit::Visit;
use syn::{ImplItemFn, ItemFn};

use super::common::{body_token_text, body_writes_state};
use super::{body_has_guard, last_segment_is, snippet_at, Rule};
use crate::abi::AbiIndex;
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct UpgradePath;

const RULE_ID: &str = "NS006";
const TITLE: &str = "Unguarded state write reachable from a public function";
const REFS: &[&str] = &["https://github.com/near/near-sdk-rs"];

/// Body mentions that make a state write deposit-funded (shared vocabulary
/// with NS008; a caller-covered write is not a contract-funded takeover).
const STORAGE_GUARD_MARKERS: &[&str] = &[
    "attached_deposit",
    "storage_byte_cost",
    "storage_usage",
    "storage_min_balance",
    "required_deposit",
    "unregister",
];

impl Rule for UpgradePath {
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
        // ABI gate: only an exported `pub` method (of a `#[near]` impl) or a
        // raw `#[no_mangle]` export is callable by an arbitrary account.
        if !self.abi.is_exported(ident) {
            return;
        }
        let has_private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        if has_private || body_has_guard(body) {
            return;
        }
        let writes_state = body_writes_state(body);
        if !writes_state {
            return;
        }
        // A write the caller pays for (storage costs charged against the
        // attached deposit) is managed storage, not a takeover primitive.
        let tokens = body_token_text(body);
        if STORAGE_GUARD_MARKERS
            .iter()
            .any(|marker| tokens.split_ascii_whitespace().any(|tn| tn == *marker))
        {
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
