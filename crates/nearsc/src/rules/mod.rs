//! Rule registry.
//!
//! Every rule is registered explicitly so the v0.1 catalog is auditable in one
//! place. `rules/*.toml` metadata is embedded in later releases; the matcher
//! registry here is the source of truth for what actually runs.

pub mod arbitrary_promise_target;
pub mod balance_drain;
pub mod callback_not_private;
pub mod callback_panic;
pub mod common;
pub mod deposit_refund_missing;
pub mod guard;
pub mod init_ignore_state;
pub mod insecure_randomness;
pub mod manifest_overflow_checks;
pub mod one_yocto_missing;
pub mod privileged_setter;
pub mod storage_griefing;
pub mod unbounded_iteration;
pub mod unchecked_promise_result;
pub mod upgrade_path;

use syn::Attribute;

use crate::engine::FileContext;
use crate::finding::Finding;

/// A rule consumes a parsed file and returns zero or more findings.
pub trait Rule {
    fn id(&self) -> &'static str;
    fn check(&self, context: &FileContext) -> Vec<Finding>;
}

/// A manifest rule consumes one `Cargo.toml` of the scan.
pub trait ManifestRule {
    fn id(&self) -> &'static str;
    fn check(&self, context: &crate::engine::ManifestContext) -> Vec<Finding>;
}

/// Every registered manifest rule.
pub fn manifest_rules() -> &'static [&'static dyn ManifestRule] {
    &[&manifest_overflow_checks::ManifestOverflowChecks]
}

/// Static catalog entry for the v0.1 rule set.
#[derive(serde::Serialize)]
pub struct RuleMeta {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: crate::finding::Severity,
    pub confidence: crate::finding::Confidence,
    /// Matcher module name; `None` marks a planned (not yet implemented) rule.
    pub matcher: Option<&'static str>,
    pub status: &'static str,
    pub refs: &'static [&'static str],
}

/// The v0.1 catalog (plan section 4). Values mirror docs/RULES.md; the parity
/// test below keeps registered matchers and this table in sync.
pub const CATALOG: &[RuleMeta] = &[
    RuleMeta {
        id: "NS001",
        title: "one-yocto-missing-on-transfer",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Spec,
        matcher: Some("one_yocto_missing"),
        status: "shipped",
        refs: &[
            "https://nomicon.io/Standards/Tokens/FungibleToken/Core",
            "https://nomicon.io/Standards/Tokens/NonFungibleToken/Core",
            "https://docs.near.org/protocol/accounts-contracts/access-keys.md",
        ],
    },
    RuleMeta {
        id: "NS002",
        title: "callback-not-private",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Spec,
        matcher: Some("callback_not_private"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/security/cross-contract-calls/callbacks.md"],
    },
    RuleMeta {
        id: "NS003",
        title: "callback-panic-risk",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("callback_panic"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS004",
        title: "unchecked-promise-result",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("unchecked_promise_result"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS005",
        title: "init-ignore-state-unguarded",
        severity: crate::finding::Severity::Critical,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("init_ignore_state"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS006",
        title: "upgrade-path-unguarded",
        severity: crate::finding::Severity::Critical,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("upgrade_path"),
        status: "shipped",
        refs: &["https://github.com/near/near-sdk-rs"],
    },
    RuleMeta {
        id: "NS007",
        title: "unbounded-iteration",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("unbounded_iteration"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/anatomy/optimizations"],
    },
    RuleMeta {
        id: "NS008",
        title: "storage-griefing",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("storage_griefing"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/anatomy/optimizations"],
    },
    RuleMeta {
        id: "NS009",
        title: "insecure-randomness",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("insecure_randomness"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/security/random"],
    },
    RuleMeta {
        id: "NS010",
        title: "arbitrary-promise-target",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("arbitrary_promise_target"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/anatomy/actions"],
    },
    RuleMeta {
        id: "NS011",
        title: "deposit-refund-missing",
        severity: crate::finding::Severity::Low,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("deposit_refund_missing"),
        status: "shipped",
        refs: &["https://docs.near.org/smart-contracts/anatomy/actions"],
    },
    RuleMeta {
        id: "NS012",
        title: "privileged-setter-unguarded",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("privileged_setter"),
        status: "shipped",
        refs: &["https://docs.near.org/protocol/accounts-contracts/access-keys.md"],
    },
    RuleMeta {
        id: "NS013",
        title: "balance-drain-transfer",
        severity: crate::finding::Severity::High,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("balance_drain"),
        status: "shipped",
        refs: &["https://github.com/near-daos/sputnik-dao-contract/issues/239"],
    },
    RuleMeta {
        id: "NS014",
        title: "release-profile-overflow-checks",
        severity: crate::finding::Severity::Medium,
        confidence: crate::finding::Confidence::Heuristic,
        matcher: Some("manifest_overflow_checks"),
        status: "shipped",
        refs: &["https://doc.rust-lang.org/cargo/reference/profiles.html"],
    },
];

/// Every registered rule, in catalog order. `run_all` and the parity test
/// both consume this slice; there is no parallel id list to drift.
pub fn rules() -> &'static [&'static dyn Rule] {
    &[
        &one_yocto_missing::OneYoctoMissing,
        &callback_not_private::CallbackNotPrivate,
        &callback_panic::CallbackPanic,
        &unchecked_promise_result::UncheckedPromiseResult,
        &init_ignore_state::InitIgnoreState,
        &upgrade_path::UpgradePath,
        &privileged_setter::PrivilegedSetter,
        &unbounded_iteration::UnboundedIteration,
        &storage_griefing::StorageGriefing,
        &insecure_randomness::InsecureRandomness,
        &arbitrary_promise_target::ArbitraryPromiseTarget,
        &deposit_refund_missing::DepositRefundMissing,
        &balance_drain::BalanceDrainTransfer,
    ]
}

/// Run every registered rule against one file.
pub fn run_all(context: &FileContext) -> Vec<Finding> {
    rules()
        .iter()
        .flat_map(|rule| rule.check(context))
        .collect()
}

/// Run every registered manifest rule against one `Cargo.toml`.
pub fn run_all_manifest(context: &crate::engine::ManifestContext) -> Vec<Finding> {
    manifest_rules()
        .iter()
        .flat_map(|rule| rule.check(context))
        .collect()
}

/// True when an attribute's path ends with `name` (`#[private]`, `#[init]`, ...).
pub fn last_segment_is(attr: &Attribute, name: &str) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == name)
}

/// The source line at `line` (1-based), trimmed; empty when out of range.
pub fn snippet_at(context: &FileContext, line: usize) -> String {
    context
        .source
        .lines()
        .nth(line.saturating_sub(1))
        .map(|source_line| source_line.trim().to_string())
        .unwrap_or_default()
}

pub use guard::{body_has_guard, body_has_guard_with};
