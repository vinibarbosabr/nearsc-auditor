//! NS012: privileged setter reachable without an access-control guard.
//!
//! Public methods named `set_*`, `update_*`, `pause_*`, `unpause_*`,
//! `withdraw_*`, or `admin_*` change contract configuration or move funds.
//! NEAR has implicit authorization: without `#[private]` or a
//! predecessor/owner check, any account can call them. The naming convention
//! reveals intent; a setter without a guard is a bug or a missing attribute
//! either way, so the rule flags both for review.
//!
//! v0.1 scope: exported (ABI) functions only — `pub` methods of `#[near]`
//! impl blocks and raw `#[no_mangle]` exports. Internal helpers and methods
//! on non-contract types are not caller-reachable and are not flagged.

use syn::visit::Visit;
use syn::{ImplItemFn, ItemFn};

use super::common::body_writes_state;
use super::{body_has_guard_with, last_segment_is, snippet_at, Rule};
use crate::abi::AbiIndex;
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct PrivilegedSetter;

const RULE_ID: &str = "NS012";
const TITLE: &str = "Privileged setter without a guard";
const REFS: &[&str] = &["https://docs.near.org/protocol/accounts-contracts/access-keys.md"];

/// Name prefixes that signal privileged configuration or fund movement.
const SETTER_PREFIXES: &[&str] = &[
    "set_",
    "update_",
    "pause_",
    "unpause_",
    "withdraw_",
    "admin_",
];

impl Rule for PrivilegedSetter {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn check(&self, context: &FileContext) -> Vec<Finding> {
        let mut collector = Collector {
            abi: &context.abi,
            context,
            fns: Vec::new(),
        };
        collector.visit_file(&context.ast);
        collector.into_findings(context)
    }
}

struct Collector<'a> {
    abi: &'a AbiIndex,
    /// The owning `FileContext`, for the delegated-guard helper index.
    context: &'a FileContext,
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
                    "public setter `{}` changes privileged state or moves funds without a guard; restrict it with #[private] or assert predecessor == owner/current_account_id",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(
        &mut self,
        context: &FileContext,
        ident: &syn::Ident,
        attrs: &[syn::Attribute],
        body: &syn::Block,
    ) {
        let name = ident.to_string();
        let privileged_name = SETTER_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));
        if !privileged_name {
            return;
        }
        // ABI gate: internal helpers (`update_action_log` free fns,
        // `Policy::update_*` plain impls, `pub(crate)`) are not
        // caller-reachable.
        if !self.abi.is_exported(ident) {
            return;
        }
        let private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        // Delegated-guard credit: a `self.assert_owner()` helper defined in
        // the same file (the sputnikdao-factory2 shape) counts as a guard.
        if private || body_has_guard_with(body, &context.guard_helpers) {
            return;
        }
        // Direct state writes fall under NS006 (critical, whole-function
        // verdict). Reporting the same function here too would double-count a
        // single access-control bug, so NS012 skips those bodies and stays the
        // config/privilege-election reviewer.
        if body_writes_state(body) {
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

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.push_fn(self.context, &item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.push_fn(self.context, &item.sig.ident, &item.attrs, &item.block);
        syn::visit::visit_impl_item_fn(self, item);
    }
}
