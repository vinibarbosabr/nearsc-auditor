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

impl crate::engine::Summary {
    /// Recount from a (possibly filtered) findings list so the summary always
    /// matches what is reported.
    pub fn recount(&mut self, findings: &[crate::finding::Finding]) {
        self.critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        self.high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        self.medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        self.low = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        self.info = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();
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

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Spec => "spec",
            Confidence::Heuristic => "heuristic",
        }
    }
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
