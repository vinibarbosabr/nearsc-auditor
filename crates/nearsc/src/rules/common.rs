//! Helpers shared by more than one matcher.
//!
//! Everything here is a pure probe over a parsed body or expression: no I/O,
//! no network, no state. A helper earns its place in this module by being
//! duplicated in rule files first; the fixture suite keeps its behavior
//! pinned. (See the copies of `body_writes_state`, `body_token_text`, and
//! `callback_name` this module replaced.)

use syn::visit::Visit;
use syn::Expr;

/// Does the body call `state_write` (e.g. `env::state_write(...)`), directly
/// or inside a macro?
///
/// Shared verdict shape: NS006 (upgrade-path) reports the whole-function
/// finding, and NS012 (privileged-setter) defers to it so one access-control
/// bug lands on one rule.
pub(crate) fn body_writes_state(block: &syn::Block) -> bool {
    #[derive(Default)]
    struct WriteProbe {
        writes: bool,
    }

    impl<'ast> Visit<'ast> for WriteProbe {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "state_write" {
                self.writes = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                if let Some(segment) = path.path.segments.last() {
                    if segment.ident == "state_write" {
                        self.writes = true;
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
                .is_some_and(|segment| segment.ident == "state_write")
            {
                self.writes = true;
            }
            if mac.tokens.to_string().contains("state_write") {
                self.writes = true;
            }
            syn::visit::visit_macro(self, mac);
        }
    }

    let mut probe = WriteProbe::default();
    probe.visit_block(block);
    probe.writes
}

/// Flattened identifier text of the body (macro groups included), used for
/// marker-mention scans.
pub(crate) fn body_token_text(block: &syn::Block) -> String {
    #[derive(Default)]
    struct TextProbe {
        text: String,
    }

    impl<'ast> Visit<'ast> for TextProbe {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.text.push_str(&ident.to_string());
            self.text.push(' ');
            syn::visit::visit_ident(self, ident);
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            let mut pending: Vec<proc_macro2::TokenTree> = mac.tokens.clone().into_iter().collect();
            while let Some(tree) = pending.pop() {
                match tree {
                    proc_macro2::TokenTree::Ident(ident) => {
                        self.text.push_str(&ident.to_string());
                        self.text.push(' ');
                    }
                    proc_macro2::TokenTree::Group(group) => pending.extend(group.stream()),
                    _ => {}
                }
            }
            syn::visit::visit_macro(self, mac);
        }
    }

    let mut probe = TextProbe::default();
    probe.visit_block(block);
    probe.text
}

/// Extract the callback function name from the argument to `.then(...)`.
///
/// Handles `.then(on_transfer)`, `.then(Self::on_transfer)`, and the near-sdk
/// idiom `.then(Self::ext(env::current_account_id()).on_transfer(...))`.
pub(crate) fn callback_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::MethodCall(call) => Some(call.method.to_string()),
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        },
        _ => None,
    }
}
