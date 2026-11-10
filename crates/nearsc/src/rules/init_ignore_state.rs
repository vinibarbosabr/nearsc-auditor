//! NS005: `#[init(ignore_state)]` without an access-control guard.
//!
//! `ignore_state` skips near-sdk's "state must not exist" check. A public
//! migrate/reinitialize function without `#[private]` or an explicit
//! predecessor assertion lets any account overwrite contract state.
//! Plain `#[init]` is not flagged: without `ignore_state` the call fails
//! when state already exists, so it is not the rule's target.

use syn::visit::Visit;
use syn::{ImplItemFn, ItemFn};

use super::{body_has_guard, last_segment_is, snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct InitIgnoreState;

const RULE_ID: &str = "NS005";
const TITLE: &str = "ignore_state init is not access-controlled";
const REFS: &[&str] = &["https://github.com/near/near-sdk-rs"];

impl Rule for InitIgnoreState {
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
                severity: Severity::Critical,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "ignore_state init `{}` is not access-controlled; any account can reinitialize contract state. Add #[private] or assert predecessor == current_account_id",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], body: &syn::Block) {
        let is_ignore_state_init = attrs.iter().any(|attr| {
            last_segment_is(attr, "init")
                && attr
                    .meta
                    .require_list()
                    .is_ok_and(|list| list.tokens.to_string().contains("ignore_state"))
        });
        if !is_ignore_state_init {
            return;
        }
        let has_private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        if has_private || body_has_guard(body) {
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
