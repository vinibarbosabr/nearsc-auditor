//! nearsc: a deterministic security scanner for NEAR smart contracts.
//!
//! The engine parses Rust source with `syn` and applies typed AST rules.
//! It never executes scanned code, never calls the network, and never uses an
//! LLM in the scan path.

pub mod engine;
pub mod finding;
pub mod kb;
pub mod rules;
