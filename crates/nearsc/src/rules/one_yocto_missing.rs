//! NS001: NEP-141/171 transfer without the 1-yoctoNEAR authorization check.
//!
//! The transfer methods of the fungible- and non-fungible-token standards are
//! specified to require exactly 1 yoctoNEAR of attached deposit, so the call
//! must be signed with a full-access key. Omitting the check lets a
//! function-call key move tokens within its method allowance.

use syn::visit::Visit;
use syn::{ImplItemFn, ItemFn};

use super::{snippet_at, Rule};
use crate::engine::FileContext;
use crate::finding::{Confidence, Finding, Severity};

pub struct OneYoctoMissing;

const RULE_ID: &str = "NS001";
const TITLE: &str = "Token transfer without 1-yocto check";
const REFS: &[&str] = &[
    "https://nomicon.io/Standards/Tokens/FungibleToken/Core",
    "https://nomicon.io/Standards/Tokens/NonFungibleToken/Core",
    "https://docs.near.org/protocol/accounts-contracts/access-keys.md",
];

const TRANSFER_METHODS: &[&str] = &[
    "ft_transfer",
    "ft_transfer_call",
    "nft_transfer",
    "nft_transfer_call",
];

impl Rule for OneYoctoMissing {
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
    /// Every transfer-shaped method: name, guarded, body of each local helper.
    transfer_fns: Vec<FnInfo>,
    /// Name -> true when the local function body enforces the 1-yocto check.
    local_helpers: Vec<(String, bool)>,
}

struct FnInfo {
    name: String,
    guarded: bool,
    line: usize,
    column: usize,
}

impl Collector {
    fn into_findings(self, context: &FileContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for candidate in &self.transfer_fns {
            // One level of local helper resolution: `internal_transfer(...)`
            // counts as guarded when that helper asserts the deposit itself.
            let helper_guarded = candidate
                .name
                .strip_prefix("ft_")
                .or_else(|| candidate.name.strip_prefix("nft_"))
                .and_then(|rest| rest.strip_prefix("transfer"))
                .and_then(|_| {
                    self.local_helpers
                        .iter()
                        .find(|(name, _)| name == &candidate.name)
                })
                .map(|(_, guarded)| *guarded);
            if candidate.guarded || helper_guarded.unwrap_or(false) {
                continue;
            }
            findings.push(Finding {
                rule_id: RULE_ID,
                title: TITLE,
                severity: Severity::High,
                confidence: Confidence::Spec,
                file: context.file.clone(),
                line: candidate.line,
                column: candidate.column,
                snippet: snippet_at(context, candidate.line),
                message: format!(
                    "transfer method `{}` does not enforce the 1-yoctoNEAR attached deposit; add assert_one_yocto() or an equivalent check (NEP-141/171)",
                    candidate.name
                ),
                refs: REFS,
            });
        }
        findings
    }
}

/// Does this expression perform a 1-yocto check?
///
/// Recognized forms:
/// - a call or macro whose path ends in `assert_one_yocto`;
/// - a comparison where one side calls `attached_deposit` and the other is the
///   literal `1` (or `NearToken::from_yoctonear(1)` / `1` via `as_yoctonear`).
fn expr_checks_one_yocto(expr: &syn::Expr) -> bool {
    #[derive(Default)]
    struct Probe {
        assert_one_yocto: bool,
        attached_deposit: bool,
        literal_one: bool,
    }

    impl<'ast> Visit<'ast> for Probe {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "assert_one_yocto" {
                self.assert_one_yocto = true;
            }
            if call.method == "attached_deposit" {
                self.attached_deposit = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                if let Some(segment) = path.path.segments.last() {
                    if segment.ident == "assert_one_yocto" {
                        self.assert_one_yocto = true;
                    }
                    if segment.ident == "attached_deposit" {
                        self.attached_deposit = true;
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
                .is_some_and(|segment| segment.ident == "assert_one_yocto")
            {
                self.assert_one_yocto = true;
            }
            let tokens = mac.tokens.to_string();
            if tokens.contains("assert_one_yocto") {
                self.assert_one_yocto = true;
            }
            if tokens.contains("attached_deposit") {
                self.attached_deposit = true;
            }
            syn::visit::visit_macro(self, mac);
        }

        fn visit_lit(&mut self, lit: &'ast syn::Lit) {
            if let syn::Lit::Int(int) = lit {
                if int.base10_digits() == "1" {
                    self.literal_one = true;
                }
            }
        }
    }

    let mut probe = Probe::default();
    if let syn::Expr::Binary(binary) = expr {
        // A comparison: attached_deposit on one side, 1 on the other.
        probe.visit_expr(expr);
        if probe.attached_deposit && probe.literal_one {
            return true;
        }
        // Attached deposit compared against a non-1 constant (e.g. from_yoctonear(1))
        // is detected through the tokens of the other operand.
        let other = tokens_of(&binary.right).contains("from_yoctonear")
            || tokens_of(&binary.left).contains("from_yoctonear");
        if probe.attached_deposit && other {
            return true;
        }
        return false;
    }
    probe.visit_expr(expr);
    probe.assert_one_yocto
}

fn tokens_of(expr: &syn::Expr) -> String {
    let mut tokens = String::new();
    let mut visitor = TokensVisitor { out: &mut tokens };
    visitor.visit_expr(expr);
    tokens
}

struct TokensVisitor<'a> {
    out: &'a mut String,
}

impl<'ast, 'a> Visit<'ast> for TokensVisitor<'a> {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.out.push_str(&mac.tokens.to_string());
        syn::visit::visit_macro(self, mac);
    }
}

impl Collector {
    fn push_fn(&mut self, ident: &syn::Ident, _attrs: &[syn::Attribute], body: &syn::Block) {
        let name = ident.to_string();
        let is_transfer = TRANSFER_METHODS.contains(&name.as_str());
        // Any local function is a potential helper; only transfers are reported.
        let guarded = body.stmts.iter().any(stmt_checks_one_yocto);
        if is_transfer {
            let start = ident.span().start();
            self.transfer_fns.push(FnInfo {
                name,
                guarded,
                line: start.line,
                column: start.column + 1,
            });
        } else if guarded {
            self.local_helpers.push((name, true));
        }
    }
}

fn stmt_checks_one_yocto(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Expr(expr, ..) => expr_checks_one_yocto(expr),
        syn::Stmt::Local(local) => local
            .init
            .as_ref()
            .is_some_and(|init| expr_checks_one_yocto(&init.expr)),
        _ => false,
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
