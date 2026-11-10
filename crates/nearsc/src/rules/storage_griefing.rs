//! NS008: storage griefing: attacker-funded storage growth.
//!
//! Every byte a contract stores must be bought with NEAR. A public method
//! that inserts caller-controlled data into a collection without an attached
//! deposit or a storage-management check lets anyone stake the contract's
//! balance away, one call at a time.
//!
//! v0.1 scope (heuristic): flag `insert`/`set`/`insert_id` calls on `self.`
//! collections in public, non-`#[payable]` methods when the body never
//! mentions `attached_deposit` or a storage-management check
//! (`storage_usage`, `storage_min_balance`, `unregister`). `#[private]`
//! callbacks and `#[init]` constructors are exempt; `#[payable]` methods are
//! exempt because an attached deposit accompanies every call.

use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

use super::{last_segment_is, snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct StorageGriefing;

const RULE_ID: &str = "NS008";
const TITLE: &str = "Caller-funded storage without a deposit check";
const REFS: &[&str] = &["https://docs.near.org/smart-contracts/anatomy/optimizations"];

/// Collection-writing method names (near-sdk maps/vectors and std maps).
const WRITE_METHODS: &[&str] = &["insert", "set", "insert_id", "insert_checked"];

/// Body mentions that make the storage paid for or managed.
const STORAGE_GUARD_MARKERS: &[&str] = &[
    "attached_deposit",
    "storage_usage",
    "storage_min_balance",
    "unregister",
    "storage_byte_cost",
    "required_deposit",
    // Documented exemption marker for rewrites of already-staked entries:
    // a contract calls this to state that the write replaces an existing
    // record instead of growing the collection.
    "rewrite_existing_entry_marker",
];

impl Rule for StorageGriefing {
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
                severity: Severity::Medium,
                confidence: Confidence::Heuristic,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "public method `{}` stores caller-controlled data without an attached deposit or storage check; charging for storage (or requiring it up front) keeps the contract's balance from being drained",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, attrs: &[syn::Attribute], body: &syn::Block) {
        let private = attrs.iter().any(|attr| last_segment_is(attr, "private"));
        let init = attrs.iter().any(|attr| last_segment_is(attr, "init"));
        let payable = attrs.iter().any(|attr| last_segment_is(attr, "payable"));
        if private || init || payable {
            return;
        }
        let mut probe = WriteProbe::default();
        probe.visit_block(body);
        if !probe.writes_collection {
            return;
        }
        let tokens = body_tokens(body);
        if STORAGE_GUARD_MARKERS
            .iter()
            .any(|marker| tokens.iter().any(|tn| tn == marker))
        {
            return;
        }
        let (line, column) = probe
            .first_write
            .expect("writes_collection implies first_write");
        self.fns.push(FnInfo {
            name: ident.to_string(),
            line,
            column,
        });
    }
}

#[derive(Default)]
struct WriteProbe {
    writes_collection: bool,
    first_write: Option<(usize, usize)>,
}

impl<'ast> Visit<'ast> for WriteProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if WRITE_METHODS.contains(&call.method.to_string().as_str())
            && is_self_collection_receiver(&call.receiver)
            && self.first_write.is_none()
        {
            let start = call.method.span().start();
            self.first_write = Some((start.line, start.column + 1));
        }
        if WRITE_METHODS.contains(&call.method.to_string().as_str())
            && is_self_collection_receiver(&call.receiver)
        {
            self.writes_collection = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// The receiver chain must be rooted at `self` (a `self.field` write), not a
/// local temporary.
fn is_self_collection_receiver(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(call) => is_self_collection_receiver(&call.receiver),
        Expr::Reference(reference) => is_self_collection_receiver(&reference.expr),
        Expr::Field(field) => is_self_expr(&field.base),
        Expr::Path(path) => path.path.segments.len() == 1 && path.path.segments[0].ident == "self",
        _ => false,
    }
}

fn is_self_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(path) if path.path.segments.len() == 1 && path.path.segments[0].ident == "self")
}

/// All identifier spellings in the body, flattened through macro groups,
/// for guard-marker scans (token-based like the other rules).
fn body_tokens(block: &syn::Block) -> Vec<String> {
    let mut out = Vec::new();
    collect_idents(block, &mut out);
    out
}

fn collect_idents(block: &syn::Block, out: &mut Vec<String>) {
    #[derive(Default)]
    struct IdentProbe {
        idents: Vec<String>,
    }

    impl<'ast> Visit<'ast> for IdentProbe {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.idents.push(ident.to_string());
            syn::visit::visit_ident(self, ident);
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            let mut pending: Vec<proc_macro2::TokenTree> = mac.tokens.clone().into_iter().collect();
            while let Some(tree) = pending.pop() {
                if let proc_macro2::TokenTree::Ident(ident) = tree {
                    self.idents.push(ident.to_string());
                } else if let proc_macro2::TokenTree::Group(group) = tree {
                    pending.extend(group.stream());
                }
            }
            syn::visit::visit_macro(self, mac);
        }
    }

    let mut probe = IdentProbe::default();
    probe.visit_block(block);
    out.extend(probe.idents);
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
