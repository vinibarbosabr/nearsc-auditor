//! Rule registry.
//!
//! Every rule is registered explicitly so the v0.1 catalog is auditable in one
//! place. `rules/*.toml` metadata is embedded in later releases; the matcher
//! registry here is the source of truth for what actually runs.

pub mod callback_not_private;

use crate::engine::FileContext;
use crate::finding::Finding;

/// A rule consumes a parsed file and returns zero or more findings.
pub trait Rule {
    fn id(&self) -> &'static str;
    fn check(&self, context: &FileContext) -> Vec<Finding>;
}

/// Run every registered rule against one file.
pub fn run_all(context: &FileContext) -> Vec<Finding> {
    let rules: &[&dyn Rule] = &[&callback_not_private::CallbackNotPrivate];
    rules.iter().flat_map(|rule| rule.check(context)).collect()
}
