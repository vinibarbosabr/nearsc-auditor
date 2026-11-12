//! NS001: NEP-141/171 transfer without the 1-yoctoNEAR authorization check.
//!
//! The transfer methods of the fungible- and non-fungible-token standards are
//! specified to require exactly 1 yoctoNEAR of attached deposit, so the call
//! must be signed with a full-access key. Omitting the check lets a
//! function-call key move tokens within its method allowance.

use proc_macro2::TokenTree;
use syn::visit::Visit;
use syn::{Expr, ImplItemFn, ItemFn};

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
    /// Every transfer-shaped method: name, direct guard flag, callee names.
    transfer_fns: Vec<FnInfo>,
    /// Locally defined functions whose body checks the 1-yocto deposit.
    guard_helpers: Vec<String>,
}

struct FnInfo {
    name: String,
    guarded: bool,
    /// Names of zero-or-more local helpers this fn calls.
    callees: Vec<String>,
    /// `Some((field, method))` when the body's only transfer-relevant call is
    /// `self.<field>.<method>(...)` — the delegation shape. `field` is the
    /// state field the call is rooted at.
    delegation: Option<(String, String)>,
    line: usize,
    column: usize,
}

/// Transfer methods whose delegation target (a near-contract-standards
/// `FungibleToken`/`NonFungibleToken`/`StorageManagement` field) already
/// enforces the 1-yocto check internally.
const STANDARDS_DELEGATION_FIELDS: &[&str] = &[
    "token",
    "ft",
    "fungible_token",
    "nft",
    "nonfungible_token",
    "non_fungible_token",
    "storage_management",
    "nft_token",
];

/// Methods that the standards implementations assert on internally
/// (near-contract-standards `core_impl.rs` `ft_transfer`/`ft_transfer_call`
/// call `assert_one_yocto()`).
const STANDARDS_GUARDED_METHODS: &[&str] = &[
    "ft_transfer",
    "ft_transfer_call",
    "nft_transfer",
    "nft_transfer_call",
];

impl Collector {
    fn into_findings(self, context: &FileContext) -> Vec<Finding> {
        // Two passes over the transfer fns: resolve guarded candidates first
        // (a helper defined later in the file still counts), then report.
        let helper_guarded = |callees: &[String]| {
            callees
                .iter()
                .any(|callee| self.guard_helpers.iter().any(|h| h == callee))
        };
        let standards_delegated = |fn_info: &FnInfo| {
            fn_info.delegation.as_ref().is_some_and(|(field, method)| {
                STANDARDS_DELEGATION_FIELDS.contains(&field.as_str())
                    && STANDARDS_GUARDED_METHODS.contains(&method.as_str())
            })
        };
        let unguarded: Vec<&FnInfo> = self
            .transfer_fns
            .iter()
            .filter(|candidate| {
                !candidate.guarded
                    && !helper_guarded(&candidate.callees)
                    && !standards_delegated(candidate)
            })
            .collect();
        unguarded
            .into_iter()
            .map(|candidate| Finding {
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
            })
            .collect()
    }
}

/// Does this expression perform a 1-yocto check?
///
/// Recognized forms:
/// - a call or macro whose path ends in `assert_one_yocto`;
/// - a comparison where one side calls `attached_deposit` and the other is the
///   literal `1`, or where the operand tokens mention a `from_yoctonear(1)`
///   call;
/// - the same comparison as the condition of an `if` statement (the idiomatic
///   `if attached_deposit != from_yoctonear(1) { panic }` guard);
/// - a comparison inside `assert!`/`assert_eq!`/`require!`, probed token-wise
///   the same way.
///
/// Macro checks are token-based: a comparison hidden behind an exotic macro
/// that does not name `attached_deposit` or `assert_one_yocto` is still
/// reported. A zero-yocto comparison (`!= from_yoctonear(0)`) is not a guard
/// and is reported.
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
    if matches!(expr, syn::Expr::Binary(_)) {
        // A comparison: attached_deposit on one side, 1 on the other.
        probe.visit_expr(expr);
        if probe.attached_deposit && probe.literal_one {
            return true;
        }
        // A `from_yoctonear(1)` call wraps the literal; the literal is still
        // in the visited tokens, so this also covers
        // `attached_deposit != from_yoctonear(1)`.
        return false;
    }
    if let syn::Expr::If(if_expr) = expr {
        // `if env::attached_deposit() != NearToken::from_yoctonear(1)
        //  { env::panic_str(...) }` is the idiomatic guard: the check lives
        // in the condition. Probe it like the bare-binary case. A condition
        // that is not a comparison falls through to the whole-expression
        // visit below (e.g. an `if` whose body asserts the deposit).
        if matches!(*if_expr.cond, syn::Expr::Binary(_)) {
            probe.visit_expr(&if_expr.cond);
            return probe.attached_deposit && probe.literal_one;
        }
    }
    probe.visit_expr(expr);
    probe.assert_one_yocto
}

impl Collector {
    fn push_fn(&mut self, ident: &syn::Ident, _attrs: &[syn::Attribute], body: &syn::Block) {
        let name = ident.to_string();
        let is_transfer = TRANSFER_METHODS.contains(&name.as_str());
        let guarded = body.stmts.iter().any(stmt_checks_one_yocto);
        if is_transfer {
            let start = ident.span().start();
            let callees = body_callee_names(body);
            let delegation = body_delegation(body, &name);
            self.transfer_fns.push(FnInfo {
                name,
                guarded,
                callees,
                delegation,
                line: start.line,
                column: start.column + 1,
            });
        } else if guarded {
            self.guard_helpers.push(name);
        }
    }
}

/// The pure-delegation shape: the whole body is one
/// `self.<field>.<same-method>(...)` tail call (optionally with `return`),
/// where `<field>` is a token state (near-contract-standards
/// `FungibleToken`/`NonFungibleToken`/`StorageManagement`). The standards
/// implementation performs the 1-yocto assertion internally, so the wrapper
/// is guarded by delegation.
///
/// Restricted to the exact wrapper idiom (single statement, same method
/// name) so any additional logic — pre-checks, extra calls, transformed
/// arguments — keeps the plain matcher verdict.
fn body_delegation(block: &syn::Block, method: &str) -> Option<(String, String)> {
    let stmt_count = block
        .stmts
        .iter()
        .filter(|stmt| !matches!(stmt, syn::Stmt::Item(_)))
        .count();
    if stmt_count != 1 {
        return None;
    }
    let method_owned = method.to_string();
    let mut probe = DelegateProbe {
        method: method_owned,
        delegation: None,
        other_calls: false,
    };
    probe.visit_block(block);
    if probe.other_calls {
        return None;
    }
    probe
        .delegation
        .filter(|(field, _)| STANDARDS_DELEGATION_FIELDS.contains(&field.as_str()))
}

struct DelegateProbe {
    method: String,
    delegation: Option<(String, String)>,
    other_calls: bool,
}

impl<'ast> Visit<'ast> for DelegateProbe {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method_matches = call.method == self.method;
        if self.delegation.is_none() && method_matches && is_self_field_receiver(&call.receiver) {
            self.delegation = Some((self_field_name(&call.receiver), call.method.to_string()));
        } else if !method_matches {
            // Any other method call (deposit reads, storage probes,
            // logging) means the body does more than delegate.
            self.other_calls = true;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        // Free-function calls (env::*, serde, ...) in the body also
        // disqualify the pure-delegation shape.
        self.other_calls = true;
        syn::visit::visit_expr_call(self, call);
    }
}

/// The receiver chain rooted at a `self.<field>` access; returns the field
/// name (`self.token.ft_transfer` -> `token`).
fn self_field_name(expr: &Expr) -> String {
    match expr {
        Expr::Field(field) => match (&*field.base, &field.member) {
            (Expr::Path(base), syn::Member::Named(member))
                if base.path.segments.len() == 1 && base.path.segments[0].ident == "self" =>
            {
                member.to_string()
            }
            _ => self_field_name(&field.base),
        },
        Expr::Reference(reference) => self_field_name(&reference.expr),
        _ => String::new(),
    }
}

/// Is this receiver chain rooted at a `self.<field>` access (not a bare
/// `self`, not a local)?
fn is_self_field_receiver(expr: &Expr) -> bool {
    match expr {
        Expr::Field(field) => match (&*field.base, &field.member) {
            (Expr::Path(base), syn::Member::Named(_))
                if base.path.segments.len() == 1 && base.path.segments[0].ident == "self" =>
            {
                true
            }
            _ => is_self_field_receiver(&field.base),
        },
        Expr::Reference(reference) => is_self_field_receiver(&reference.expr),
        _ => false,
    }
}

/// Local function/method names called anywhere in the body (one level of
/// call-depth for guard-helper resolution).
fn body_callee_names(block: &syn::Block) -> Vec<String> {
    let mut names = Vec::new();
    let mut visitor = CalleeVisitor { out: &mut names };
    visitor.visit_block(block);
    names
}

struct CalleeVisitor<'a> {
    out: &'a mut Vec<String>,
}

impl<'ast, 'a> Visit<'ast> for CalleeVisitor<'a> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.out.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        // `self.internal_transfer(...)` registers as a callee too; a same-file
        // helper is what the RULES.md false-positive note resolves.
        self.out.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn stmt_checks_one_yocto(stmt: &syn::Stmt) -> bool {
    match stmt {
        syn::Stmt::Expr(expr, ..) => expr_checks_one_yocto(expr),
        syn::Stmt::Local(local) => local
            .init
            .as_ref()
            .is_some_and(|init| expr_checks_one_yocto(&init.expr)),
        syn::Stmt::Macro(stmt_mac) => {
            // A bare `assert!(...)`/`assert_eq!(...)`/`require!(...)` statement
            // is a `Stmt::Macro`, so the comparison never reaches the binary
            // branch above. Probe the macro tokens for an attached_deposit
            // identifier together with the literal `1`. Token-based, same
            // limits as `Probe`: a zero-yocto argument (`from_yoctonear(0)`)
            // carries no `1` literal and stays reported.
            let mut has_deposit = false;
            let mut has_one = false;
            let mut pending: Vec<TokenTree> = stmt_mac.mac.tokens.clone().into_iter().collect();
            while !(has_deposit && has_one) {
                let Some(tree) = pending.pop() else {
                    break;
                };
                match tree {
                    TokenTree::Ident(ident) => {
                        has_deposit |= ident == "attached_deposit";
                    }
                    TokenTree::Literal(lit) => {
                        has_one |= lit.to_string() == "1";
                    }
                    TokenTree::Group(group) => {
                        pending.extend(group.stream());
                    }
                    TokenTree::Punct(_) => {}
                }
            }
            has_deposit && has_one
        }
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
