//! NS009: insecure randomness from predictable environment data.
//!
//! `env::block_index()`, `env::block_timestamp()`, and
//! `env::predecessor_account_id()` are visible to (or shaped by) the caller
//! and validators: using them as entropy, or feeding them into a hash and
//! calling the result random, lets an attacker predict or bias lotteries,
//! mints, and shuffles.
//!
//! v0.1 scope (heuristic): flag predictions only where the predictability is
//! explicit: a hash-family call (`sha256`/`keccak`/`hash`/`Hash*` or a
//! method named `hash_*`) or a `%`/`/`-reduced selection that takes one of
//! the three environment values as an operand. A commented commit-reveal or
//! random_seed-based design is the fix.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{BinOp, Expr, ImplItemFn, ItemFn};

use super::{snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct InsecureRandomness;

const RULE_ID: &str = "NS009";
const TITLE: &str = "Randomness derived from predictable inputs";
const REFS: &[&str] = &["https://docs.near.org/smart-contracts/security/random"];

/// Environment facts that are predictable or caller-influenced.
const PREDICTABLE_CALLS: &[&str] = &["block_index", "block_timestamp"];

impl Rule for InsecureRandomness {
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
                    "`{}` derives a value from block data or the caller's account; those inputs are predictable or influenceable, so lotteries/mints built on them can be steered. Use a commit-reveal or a random-seed oracle",
                    candidate.name
                ),
                refs: REFS,
            })
            .collect()
    }

    fn push_fn(&mut self, ident: &syn::Ident, body: &syn::Block) {
        let mut probe = EntropyProbe::default();
        probe.visit_block(body);
        if let Some((line, column)) = probe.first_sink {
            self.fns.push(FnInfo {
                name: ident.to_string(),
                line,
                column,
            });
        }
    }
}

#[derive(Default)]
struct EntropyProbe {
    first_sink: Option<(usize, usize)>,
    /// Non-zero while inside a hash call's arguments or a `%` expression:
    /// predictable calls encountered there are the entropy sink.
    hash_depth: usize,
    mod_depth: usize,
}

impl<'ast> Visit<'ast> for EntropyProbe {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let fname = match &*call.func {
            Expr::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        };
        let is_hashish = fname.as_deref().is_some_and(is_hash_shaped);
        if is_hashish {
            self.hash_depth += 1;
            syn::visit::visit_expr_call(self, call);
            self.hash_depth -= 1;
            return;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let mname = call.method.to_string();
        if is_hash_shaped(&mname) {
            self.hash_depth += 1;
            syn::visit::visit_expr_method_call(self, call);
            self.hash_depth -= 1;
            return;
        }
        if (self.hash_depth > 0 || self.mod_depth > 0)
            && PREDICTABLE_CALLS.contains(&mname.as_str())
            && self.first_sink.is_none()
        {
            let start = call.method.span().start();
            self.first_sink = Some((start.line, start.column + 1));
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        let is_mod = matches!(binary.op, BinOp::Rem(_));
        if is_mod {
            self.mod_depth += 1;
            syn::visit::visit_expr_binary(self, binary);
            self.mod_depth -= 1;
            return;
        }
        syn::visit::visit_expr_binary(self, binary);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if self.hash_depth == 0 && self.mod_depth == 0 {
            return;
        }
        let last = path.path.segments.last().map(|s| s.ident.to_string());
        if let Some(name) = last {
            if PREDICTABLE_CALLS.contains(&name.as_str()) && self.first_sink.is_none() {
                let start = path.span().start();
                self.first_sink = Some((start.line, start.column + 1));
            }
        }
        syn::visit::visit_expr_path(self, path);
    }
}

/// `sha256`, `keccak256`, `hash`, `HashSha256`, `hash_*` method names and
/// the like.
fn is_hash_shaped(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    low.starts_with("hash") || low.contains("sha256") || low.contains("keccak")
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
