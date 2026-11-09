use serde::Serialize;

/// Severity of a finding, ordered from most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// How the rule reaches its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The pattern violates NEAR protocol or near-sdk semantics.
    Spec,
    /// The pattern is suspicious but may be intentional; a human must confirm.
    Heuristic,
}

/// One scanner finding. Field names follow the public JSON schema (plan section 5.1).
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub message: String,
    pub refs: &'static [&'static str],
}
