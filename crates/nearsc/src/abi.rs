//! The contract's callable surface (ABI).
//!
//! Rules that report "any account can call this" need to know which
//! functions an account can actually call. On NEAR the ABI is:
//!
//! - `pub` methods of `#[near]` / `#[near_bindgen]` impl blocks (the macro
//!   registers the exported methods), and
//! - free functions exported raw through `#[no_mangle]`, in any spelling
//!   (`#[unsafe(no_mangle)]`, `#[cfg_attr(target_arch = "wasm32",
//!   unsafe(no_mangle))]`).
//!
//! `pub(crate)` and private methods, plain (non-`#[near]`) impls, free
//! helper functions, and `#[cfg(test)]` modules are internal: an attacker
//! cannot reach them directly, so ABI-targeting rules skip them. A v0.2
//! cross-function call graph will trace internal helpers to their exported
//! wrappers; until then an internal helper's bug surfaces only when the
//! exported wrapper shares the vulnerable shape.

use std::collections::HashSet;

use syn::visit::Visit;

/// Which functions in a parsed file are on the callable surface, keyed by
/// the span start of the `fn` ident.
#[derive(Debug, Default)]
pub struct AbiIndex {
    exported: HashSet<(usize, usize)>,
}

impl AbiIndex {
    pub fn build(ast: &syn::File) -> Self {
        let mut exported = HashSet::new();
        let mut collector = AbiCollector {
            exported: &mut exported,
            in_test_cfg: false,
        };
        collector.visit_file(ast);
        Self { exported }
    }

    /// Is this `fn` ident on the callable surface?
    pub fn is_exported(&self, ident: &proc_macro2::Ident) -> bool {
        let start = ident.span().start();
        self.exported.contains(&(start.line, start.column))
    }
}

struct AbiCollector<'a> {
    exported: &'a mut HashSet<(usize, usize)>,
    /// Inside a `#[cfg(test)]` module; test fns are never ABI.
    in_test_cfg: bool,
}

impl AbiCollector<'_> {
    fn insert(&mut self, ident: &proc_macro2::Ident) {
        let start = ident.span().start();
        self.exported.insert((start.line, start.column));
    }
}

impl<'ast> Visit<'ast> for AbiCollector<'_> {
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        // Exported impl: `#[near]` (near-sdk v2) or `#[near_bindgen]` (v1).
        // `pub` methods of such an impl are registered on the ABI; trait
        // impls (`impl Trait for X`) are treated the same way.
        if !self.in_test_cfg && !attrs_cfg_test(&item.attrs) && impl_is_near(item) {
            for impl_item in &item.items {
                if let syn::ImplItem::Fn(fn_item) = impl_item {
                    if matches!(fn_item.vis, syn::Visibility::Public(_)) {
                        self.insert(&fn_item.sig.ident);
                    }
                }
            }
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        // Free functions reach the ABI only through a raw no-mangle export.
        if !self.in_test_cfg
            && !attrs_cfg_test(&item.attrs)
            && item.attrs.iter().any(attr_is_no_mangle)
        {
            self.insert(&item.sig.ident);
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let saved = self.in_test_cfg;
        if attrs_cfg_test(&item.attrs) {
            self.in_test_cfg = true;
        }
        syn::visit::visit_item_mod(self, item);
        self.in_test_cfg = saved;
    }
}

/// `#[near]` / `#[near_bindgen]` impl block (the path's last segment).
fn impl_is_near(item: &syn::ItemImpl) -> bool {
    item.attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "near" || segment.ident == "near_bindgen")
    })
}

/// A `#[cfg(...test...)]` attribute.
fn attrs_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("cfg") && format!("{:?}", attr.meta).contains("test"))
}

/// `#[no_mangle]`, `#[unsafe(no_mangle)]`, or a `#[cfg_attr(...)]` that
/// enables one: the raw-export spellings near-sdk contracts use.
fn attr_is_no_mangle(attr: &syn::Attribute) -> bool {
    if attr.path().is_ident("no_mangle") {
        return true;
    }
    (attr.path().is_ident("unsafe") || attr.path().is_ident("cfg_attr"))
        && format!("{:?}", attr.meta).contains("no_mangle")
}