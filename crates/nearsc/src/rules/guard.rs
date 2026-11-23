//! Guard recognition: manual caller-checks, delegated helpers, and the
//! crate-scoped helper index.
//!
//! v0.1 shipped a same-file helper index: a body calling `self.assert_owner()`
//! was credited when the same file defined that helper with a real
//! predecessor-vs-state check. The scan campaign (PotLock @ 71f35051, issue
//! #83) showed the real world spells guards one and two files away through
//! `is_*`/`assert_*` chains (`admin.rs` setter -> `internal.rs`
//! `assert_admin_or_greater` -> `is_owner_or_admin` -> `is_owner`). v0.2.0
//! widens the index to the crate: every function of the crate contributes a
//! table entry (name, base probe, callees) and a fixpoint credits a chain
//! when every same-named function in the chain passes. Only
//! `CALL_GUARD_PREFIXES` names (`assert_`, `require_`, `ensure_`, `check_`,
//! `only_`) enter the published index, so a flagged body is still credited
//! only through a guard-sounding helper call.
//!
//! Safety bar (docs/FALSE-POSITIVES.md): credit is transitive closure of the
//! base probe, which requires a source-visible `predecessor_account_id`
//! compared against `current_account_id` or contract state. Delete the leaf
//! check and the whole chain stops passing: no probable guards.

use std::collections::HashMap;

use syn::visit::Visit;
use syn::Expr;
/// Helper-name prefixes eligible for delegated-guard credit: what a flagged
/// body may call to be considered guarded.
pub(crate) const CALL_GUARD_PREFIXES: &[&str] =
    &["assert_", "require_", "ensure_", "check_", "only_"];

/// One function of one file, as seen by the crate index.
pub(crate) struct FnTable {
    pub name: String,
    /// The base probe (`body_has_guard_with(block, &[])`): the body itself
    /// performs a caller check.
    pub base_passes: bool,
    /// Names this body calls (methods on `self` and free calls, one level;
    /// the fixpoint makes this transitive).
    pub callees: Vec<String>,
}

/// Build the fn tables of one parsed file: every `fn` (impl method or free).
pub(crate) fn fn_tables(ast: &syn::File) -> Vec<FnTable> {
    #[derive(Default)]
    struct TableVisitor {
        tables: Vec<FnTable>,
    }

    impl TableVisitor {
        fn push(&mut self, ident: &syn::Ident, block: &syn::Block) {
            let mut callees = CalleeVisitor::default();
            callees.visit_block(block);
            // Macro bodies are not visited as expressions by `syn`, so calls
            // spelled inside macros (`assert!(self.is_owner(), ...)`) are
            // matched on the flattened token stream.
            callees.record_macro_tokens(block);
            let mut callees: Vec<String> = callees.names.clone();
            callees.sort();
            callees.dedup();
            self.tables.push(FnTable {
                name: ident.to_string(),
                base_passes: body_has_guard_with(block, &[]),
                callees,
            });
        }
    }

    impl<'ast> Visit<'ast> for TableVisitor {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            self.push(&item.sig.ident, &item.block);
            syn::visit::visit_item_fn(self, item);
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            self.push(&item.sig.ident, &item.block);
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    let mut visitor = TableVisitor::default();
    visitor.visit_file(ast);
    visitor.tables
}

/// Crate-scoped guard-helper index: the `CALL_GUARD_PREFIXES` names that pass
/// the base probe directly or through a chain of same-crate calls.
///
/// Name collisions are conservative: a name passes only when every same-named
/// function of the crate passes.
pub(crate) fn guard_index(tables: &[FnTable]) -> Vec<String> {
    let mut passes: HashMap<&str, bool> = HashMap::new();
    for table in tables {
        passes
            .entry(table.name.as_str())
            .and_modify(|ok| *ok = *ok && table.base_passes)
            .or_insert(table.base_passes);
    }
    // Fixpoint: a table passes when its base probe passes or any callee
    // passes. Monotone addition, so this terminates.
    loop {
        let mut changed = false;
        for table in tables {
            if passes.get(table.name.as_str()).copied().unwrap_or(false) {
                continue;
            }
            let credited = table
                .callees
                .iter()
                .any(|callee| passes.get(callee.as_str()).copied().unwrap_or(false));
            if credited {
                passes.insert(table.name.as_str(), true);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut out: Vec<String> = passes
        .into_iter()
        .filter(|(name, ok)| {
            *ok && CALL_GUARD_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .map(|(name, _)| name.to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Recognize a manual "only the contract itself may call this" guard.
///
/// Matches a body that mentions both `predecessor_account_id` and
/// `current_account_id`, an `assert_self`-style macro, a comparison of
/// `predecessor_account_id` against a `self` field (the owner-guard shape
/// the NS005/NS006/NS012 messages recommend:
/// `assert_eq!(env::predecessor_account_id(), self.owner)`), or a macro
/// invocation whose tokens mention both calls (`assert_eq!`, `require!`,
/// ...). Macro bodies are inspected as tokens because `syn` does not
/// expand them.
pub fn body_has_guard(block: &syn::Block) -> bool {
    body_has_guard_with(block, &[])
}

/// `body_has_guard` plus credit for delegated guard helpers.
///
/// A body that calls `self.assert_owner()` is guarded when the crate index
/// contains that name: some function of the crate defines it (conservatively,
/// every same-named function) and its body performs the
/// predecessor-vs-self check directly or through a chain.
pub fn body_has_guard_with(block: &syn::Block, helper_guards: &[String]) -> bool {
    let mut visitor = GuardVisitor::default();
    visitor.visit_block(block);
    visitor.assert_self
        || (visitor.predecessor && visitor.current)
        || (visitor.predecessor && visitor.self_field)
        || visitor
            .self_helper
            .is_some_and(|name| helper_guards.contains(&name))
}

/// Method names whose call reads the authorization identity from state:
/// the `self.get_owner()` shape (a method call instead of a field read).
const OWNER_GETTER_METHODS: &[&str] = &[
    "get_owner",
    "owner",
    "owner_id",
    "get_admin",
    "admin",
    "admin_id",
];

#[derive(Default)]
struct GuardVisitor {
    predecessor: bool,
    current: bool,
    self_field: bool,
    assert_self: bool,
    /// Name of a `self.assert_*()`-style helper called by the body, when the
    /// name is delegation-eligible; credited only when the name is in the
    /// crate index.
    self_helper: Option<String>,
}

impl<'ast> Visit<'ast> for GuardVisitor {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "predecessor_account_id" {
            self.predecessor = true;
        }
        if call.method == "current_account_id" {
            self.current = true;
        }
        // Owner-as-method-call: `assert_eq!(self.get_owner(),
        // env::predecessor_account_id())` is the same owner guard as the
        // `self.owner` field comparison, spelled through a getter.
        if OWNER_GETTER_METHODS.contains(&call.method.to_string().as_str())
            && is_self_rooted(&call.receiver)
        {
            self.self_field = true;
        }
        // Delegated guard shape: a bare-`self` method call whose name sounds
        // like an authorization check. Credited only when the name is in
        // the crate index (see `body_has_guard_with`).
        if self.self_helper.is_none()
            && is_self_path(&call.receiver)
            && CALL_GUARD_PREFIXES
                .iter()
                .any(|prefix| call.method.to_string().starts_with(prefix))
        {
            self.self_helper = Some(call.method.to_string());
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                if segment.ident == "predecessor_account_id" {
                    self.predecessor = true;
                }
                if segment.ident == "current_account_id" {
                    self.current = true;
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        // `self.owner`, `self.staking_id`, ...: an owner-style guard
        // compares the predecessor against a state field.
        if is_self_rooted(&field.base) {
            self.self_field = true;
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "assert_self")
        {
            self.assert_self = true;
        }
        // Macro bodies are not visited as expressions by `syn`, so the
        // guard mentions inside `assert_eq!`/`require!` are matched on
        // the flattened token stream.
        let mut pending: Vec<proc_macro2::TokenTree> = mac.tokens.clone().into_iter().collect();
        while let Some(tree) = pending.pop() {
            match tree {
                proc_macro2::TokenTree::Ident(ident) => {
                    if ident == "predecessor_account_id" {
                        self.predecessor = true;
                    }
                    if ident == "current_account_id" {
                        self.current = true;
                    }
                    if ident == "self" {
                        self.self_field = true;
                    }
                }
                proc_macro2::TokenTree::Group(group) => {
                    pending.extend(group.stream());
                }
                _ => {}
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// Names called anywhere in a body: `self.<method>(...)` methods and
/// `<path>::<fn>(...)` / `<fn>(...)` free calls (last segment). Macro bodies
/// are flattened to tokens, so `assert!(self.is_owner(), ...)` records
/// `is_owner`.
#[derive(Default)]
struct CalleeVisitor {
    names: Vec<String>,
}

impl CalleeVisitor {
    /// Record call-shaped tokens from macro bodies: `self.<name> (` and a
    /// non-path-qualified `<name> (`. Path-qualified calls (`a::b`,
    /// `x.y`) are extern or non-self and stay out.
    fn record_macro_tokens(&mut self, block: &syn::Block) {
        struct MacroCalls<'a> {
            names: &'a mut Vec<String>,
        }

        impl<'ast, 'a> Visit<'ast> for MacroCalls<'a> {
            fn visit_stmt_macro(&mut self, stmt_mac: &'ast syn::StmtMacro) {
                self.visit_stmt_macro_impl(stmt_mac);
                // No default visit: macro bodies are tokens, not AST.
            }

            fn visit_expr_macro(&mut self, expr_mac: &'ast syn::ExprMacro) {
                self.visit_expr_macro_impl(expr_mac);
                // No default visit: macro bodies are tokens, not AST.
            }
        }

        impl<'ast, 'a> MacroCalls<'a> {
            fn visit_stmt_macro_impl(&mut self, stmt_mac: &'ast syn::StmtMacro) {
                self.record(&stmt_mac.mac);
                // No default visit: macro bodies are tokens, not AST.
            }

            fn visit_expr_macro_impl(&mut self, expr_mac: &'ast syn::ExprMacro) {
                self.record(&expr_mac.mac);
                // No default visit: macro bodies are tokens, not AST.
            }

            fn record(&mut self, mac: &'ast syn::Macro) {
                // Flatten the macro's token stream into source order,
                // descending into every nested group. `group.stream()`
                // excludes the delimiters, so the call parens of
                // `self.name(...)` inside a macro arrive as an empty inner
                // group right after the callee name.
                let mut flat: Vec<proc_macro2::TokenTree> = Vec::new();
                let mut stack: Vec<proc_macro2::TokenTree> =
                    mac.tokens.clone().into_iter().collect();
                while let Some(tree) = stack.pop() {
                    match tree {
                        proc_macro2::TokenTree::Group(group) => {
                            // Popping reverses, so push the inner stream
                            // reversed to keep the final `flat` in source
                            // order.
                            let mut inner: Vec<proc_macro2::TokenTree> =
                                group.stream().into_iter().collect();
                            inner.reverse();
                            stack.extend(inner);
                        }
                        other => flat.push(other),
                    }
                }
                let mut i = 0;
                while i < flat.len() {
                    if let proc_macro2::TokenTree::Ident(ident) = &flat[i] {
                        // `self . name`: a self-rooted method call inside
                        // the macro. The call parens arrive as an empty
                        // inner group AFTER the name and end the scan.
                        if *ident == "self"
                            && i + 2 < flat.len()
                            && Self::punct_is(&flat[i + 1], '.')
                            && matches!(&flat[i + 2], proc_macro2::TokenTree::Ident(_))
                        {
                            if let proc_macro2::TokenTree::Ident(name) = &flat[i + 2] {
                                self.names.push(name.to_string());
                            }
                            i += 3;
                            continue;
                        }
                        // `name`: a bare free call inside the macro,
                        // unless path-qualified (`a::name`, `x.name`).

                        let qualified = i > 0 && Self::previous_is_path(&flat[..i]);
                        if !qualified {
                            self.names.push(ident.to_string());
                        }
                    }
                    i += 1;
                }
            }
        }

        impl<'a> MacroCalls<'a> {
            fn punct_is(tree: &proc_macro2::TokenTree, ch: char) -> bool {
                matches!(tree, proc_macro2::TokenTree::Punct(p) if p.as_char() == ch)
            }

            /// Is the ident at `flat[i]` preceded by `.` or `::`?
            fn previous_is_path(flat: &[proc_macro2::TokenTree]) -> bool {
                let i = flat.len();
                if i == 0 {
                    return false;
                }
                if Self::punct_is(&flat[i - 1], '.') {
                    return true;
                }
                i >= 2 && Self::punct_is(&flat[i - 1], ':') && Self::punct_is(&flat[i - 2], ':')
            }
        }

        let mut visitor = MacroCalls {
            names: &mut self.names,
        };
        visitor.visit_block(block);
    }
}

impl<'ast> Visit<'ast> for CalleeVisitor {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.names.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.names.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// `self` (and field/method chains rooted at `self`): the receiver of a
/// state field access or owner getter. `self` alone is a one-segment
/// path in `syn`.
fn is_self_rooted(expr: &Expr) -> bool {
    match expr {
        Expr::Path(_) => is_self_path(expr),
        Expr::Field(field) => is_self_rooted(&field.base),
        Expr::Reference(reference) => is_self_rooted(&reference.expr),
        Expr::MethodCall(call) => is_self_rooted(&call.receiver),
        _ => false,
    }
}

/// Bare `self` (a one-segment path in `syn`).
fn is_self_path(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(path) if path.path.segments.len() == 1 && path.path.segments[0].ident == "self")
}

#[cfg(test)]
mod tests {
    use super::{body_has_guard, body_has_guard_with, fn_tables, guard_index, CALL_GUARD_PREFIXES};
    use syn::parse_quote;

    #[test]
    fn detects_assert_eq_guard() {
        let block: syn::Block = parse_quote!({
            assert_eq!(env::predecessor_account_id(), env::current_account_id());
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn detects_branch_guard() {
        let block: syn::Block = parse_quote!({
            if env::predecessor_account_id() != env::current_account_id() {
                env::panic_str("only self");
            }
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn detects_assert_self_macro() {
        let block: syn::Block = parse_quote!({
            assert_self!();
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn detects_owner_field_guard() {
        // The owner-guard shape the rule messages recommend: predecessor
        // compared against a state field (`self.owner`, a trusted staking
        // contract id, ...). The macro tokens carry both mentions.
        let block: syn::Block = parse_quote!({
            assert_eq!(
                env::predecessor_account_id(),
                self.staking_id,
                "ERR_INVALID_CALLER"
            );
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn detects_owner_field_guard_call_form() {
        // Method-call form: `assert!(env::predecessor_account_id() ==
        // self.owner)` and field access under a reference both count.
        let block: syn::Block = parse_quote!({
            assert!(
                env::predecessor_account_id() == *self.owner,
                "ERR_INVALID_CALLER"
            );
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn detects_owner_getter_method_guard() {
        // The factory-2 shape: the owner identity comes from a getter method
        // call (`self.get_owner()`), not a field read. Same guard, different
        // spelling; the getter is self-rooted.
        let block: syn::Block = parse_quote!({
            assert_eq!(
                self.get_owner(),
                env::predecessor_account_id(),
                "Must be owner"
            );
        });
        assert!(body_has_guard(&block));
    }

    #[test]
    fn non_owner_getters_are_not_guard_credit() {
        // An arbitrary self method call without a guard-sounding name does
        // not satisfy the predecessor comparison when spelled as an explicit
        // expression (no macro, so no token-mention path).
        let block: syn::Block = parse_quote!({
            if self.compute_fee() == env::predecessor_account_id() {
                env::panic_str("unexpected");
            }
        });
        assert!(!body_has_guard(&block));
    }

    #[test]
    fn delegated_guard_helper_satisfies_via_index() {
        // `self.assert_owner()` alone is not a guard; with the crate index
        // (the helper body does the predecessor check) it is.
        let file: syn::File = parse_quote! {
            impl Fixture {
                fn assert_owner(&self) {
                    assert_eq!(
                        self.get_owner(),
                        env::predecessor_account_id(),
                        "Must be owner"
                    );
                }
            }
        };
        let index = guard_index(&fn_tables(&file));
        assert_eq!(index, vec!["assert_owner".to_string()]);

        let caller_block: syn::Block = parse_quote!({
            self.assert_owner();
            self.fee = fee;
        });
        assert!(
            !body_has_guard_with(&caller_block, &[]),
            "no index: not credited"
        );
        assert!(
            body_has_guard_with(&caller_block, &index),
            "same-file helper: credited"
        );
    }

    #[test]
    fn non_guard_sounding_helper_never_credits() {
        // Name-gated: a helper whose body mentions the predecessor but whose
        // name is not guard-shaped stays uncredited, and so does its caller.
        // `let caller = ...; self.x = caller;` is the bookkeeping shape; the
        // assignment makes the helper body pass the base probe via the
        // self-field mention, so the helper name would appear in the index
        // unless the name gate rejects it.
        let file: syn::File = parse_quote! {
            impl Fixture {
                fn save_user(&mut self, user: AccountId) {
                    let caller = env::predecessor_account_id();
                    self.owner = caller;
                }
            }
        };
        let index = guard_index(&fn_tables(&file));
        assert!(
            !index.iter().any(|name| name == "save_user"),
            "save_user must be name-gated out of the index: {index:?}"
        );

        let caller_block: syn::Block = parse_quote!({
            self.save_user(user);
        });
        assert!(!body_has_guard_with(&caller_block, &index));
    }

    #[test]
    fn unrelated_self_method_call_is_not_delegation() {
        // A bare-`self` call with a non-guard name (e.g. `self.refresh()`)
        // never registers as a delegated guard candidate. Note: the body
        // below also writes the predecessor into a self field
        // (`self.owner = ...`), which the base probe credits by design
        // (predecessor + self mention). To isolate the delegation channel,
        // this test pins only that `refresh` produces no helper entry, and
        // the caller-with-no-other-mentions body stays unguarded.
        let file: syn::File = parse_quote! {
            impl Fixture {
                fn refresh(&self) {}
            }
        };
        let index = guard_index(&fn_tables(&file));
        assert!(index.is_empty(), "{index:?}");

        let caller_block: syn::Block = parse_quote!({
            self.refresh();
        });
        assert!(!body_has_guard_with(&caller_block, &index));
    }

    #[test]
    fn predecessor_alone_is_not_a_guard() {
        // Reading the predecessor without comparing it to anything the
        // contract trusts is bookkeeping, not a guard. The field write here
        // is `caller`-keyed bookkeeping (insert on a state field), which
        // the guard test must not mistake for a self/owner comparison.
        let block: syn::Block = parse_quote!({
            let caller = env::predecessor_account_id();
            log(caller);
        });
        assert!(!body_has_guard(&block));
    }

    #[test]
    fn ignores_partial_or_unrelated_bodies() {
        let partial: syn::Block = parse_quote!({
            let caller = env::predecessor_account_id();
        });
        assert!(!body_has_guard(&partial));

        let unrelated: syn::Block = parse_quote!({
            env::log_str("done");
        });
        assert!(!body_has_guard(&unrelated));
    }

    #[test]
    fn prefixes_stay_guard_sounding() {
        // The published list: exactly the delegation-eligible prefixes.
        let expected = ["assert_", "require_", "ensure_", "check_", "only_"];
        assert_eq!(CALL_GUARD_PREFIXES, expected);
    }

    #[test]
    fn chain_passes_through_is_helpers() {
        // The PotLock shape (issue #83): the setter delegates through
        // assert_admin_or_greater -> is_owner_or_admin -> is_owner/is_admin,
        // none of which mentions the predecessor at the assert level.
        let file: syn::File = parse_quote! {
            impl Fixture {
                pub fn set_fee(&mut self, fee: u32) {
                    self.assert_admin_or_greater();
                    self.fee = fee;
                }
                fn assert_admin_or_greater(&self) {
                    assert!(self.is_owner_or_admin(), "admin or owner");
                }
                fn is_owner_or_admin(&self) -> bool {
                    self.is_owner() || self.is_admin()
                }
                fn is_owner(&self) -> bool {
                    env::predecessor_account_id() == self.owner
                }
                fn is_admin(&self) -> bool {
                    self.admins.contains(&env::predecessor_account_id())
                }
            }
        };
        let tables = fn_tables(&file);
        let index = guard_index(&tables);
        assert_eq!(index, vec!["assert_admin_or_greater".to_string()]);

        let caller: syn::Block = parse_quote!({
            {
                self.assert_admin_or_greater();
            }
        });
        assert!(
            body_has_guard_with(&caller, &index),
            "chain must credit the setter"
        );
        assert!(
            !body_has_guard_with(&caller, &[]),
            "without the index there is no credit"
        );
    }

    #[test]
    fn is_helpers_alone_never_enter_the_index() {
        // Chain intermediates pass the fixpoint but only guard-sounding
        // names are published: a body calling `self.is_owner()` directly
        // is never credited.
        let file: syn::File = parse_quote! {
            impl Fixture {
                fn is_owner(&self) -> bool {
                    env::predecessor_account_id() == self.owner
                }
            }
        };
        let tables = fn_tables(&file);
        assert!(
            guard_index(&tables).is_empty(),
            "is_ must not be credited directly"
        );
    }

    #[test]
    fn broken_chain_stops_the_credit() {
        // Negative control: the leaf check is missing, so the whole chain
        // fails and the setter stays unguarded.
        let file: syn::File = parse_quote! {
            impl Fixture {
                pub fn set_fee(&mut self, fee: u32) {
                    self.assert_admin_or_greater();
                    self.fee = fee;
                }
                fn assert_admin_or_greater(&self) {
                    assert!(self.is_owner_or_admin(), "admin or owner");
                }
                fn is_owner_or_admin(&self) -> bool {
                    self.is_owner() || self.is_admin()
                }
                fn is_owner(&self) -> bool {
                    self.configured
                }
                fn is_admin(&self) -> bool {
                    self.admins.is_empty()
                }
            }
        };
        let index = guard_index(&fn_tables(&file));
        assert!(index.is_empty(), "broken chain must not credit: {index:?}");
    }

    #[test]
    fn catalog_matches_the_registered_matchers() {
        let registered: Vec<&str> = crate::rules::rules().iter().map(|rule| rule.id()).collect();
        let manifest_registered: Vec<&str> = crate::rules::manifest_rules()
            .iter()
            .map(|rule| rule.id())
            .collect();

        for id in &registered {
            let entry = crate::rules::CATALOG
                .iter()
                .find(|entry| &entry.id == id)
                .unwrap_or_else(|| panic!("CATALOG missing {id}"));
            assert!(entry.matcher.is_some(), "{id} shipped but marked planned");
        }
        for entry in crate::rules::CATALOG
            .iter()
            .filter_map(|entry| entry.matcher)
        {
            let in_rules = registered.contains(
                &crate::rules::CATALOG
                    .iter()
                    .find(|candidate| candidate.matcher == Some(entry))
                    .expect("entry")
                    .id,
            );
            let in_manifest_rules = manifest_registered.contains(
                &crate::rules::CATALOG
                    .iter()
                    .find(|candidate| candidate.matcher == Some(entry))
                    .expect("entry")
                    .id,
            );
            assert!(
                in_rules || in_manifest_rules,
                "CATALOG claims matcher {entry} but run_all/run_all_manifest do not register a rule using it"
            );
        }
        for entry in crate::rules::CATALOG
            .iter()
            .filter(|entry| entry.matcher.is_none())
        {
            assert!(
                !registered.contains(&entry.id),
                "{} is registered but the catalog marks it planned",
                entry.id
            );
        }
    }
}
