//! SARIF 2.1.0 rendering.
//!
//! Minimal valid output: `version`, `$schema`, `runs[].tool.driver.rules`
//! (the registered catalog) and `runs[].results[]` (one per finding).
//! Level mapping (plan section 4): critical/high -> "error",
//! medium -> "warning", low/info -> "note". Byte-stable for the same input:
//! no timestamps, no de-dup, findings already sorted by the engine.

use serde::Serialize;

use crate::engine::ScanResult;
use crate::finding::Severity;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

#[derive(Serialize)]
struct Sarif {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<Run>,
}

#[derive(Serialize)]
struct Run {
    tool: Tool,
    results: Vec<ResultEntry>,
}

#[derive(Serialize)]
struct Tool {
    driver: Driver,
}

#[derive(Serialize)]
struct Driver {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
    #[serde(rename = "rules")]
    catalog: Vec<CatalogRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogRule {
    id: &'static str,
    name: &'static str,
    short_description: ShortDescription,
    help_uri: &'static str,
}

#[derive(Serialize)]
struct ShortDescription {
    text: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultEntry {
    rule_id: &'static str,
    level: &'static str,
    message: Message,
    locations: Vec<Location>,
    properties: ResultProperties,
}

#[derive(Serialize)]
struct Message {
    text: String,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: usize,
    start_column: usize,
}

#[derive(Serialize)]
struct ResultProperties {
    severity: &'static str,
    confidence: &'static str,
}

/// Render a finished scan as a SARIF 2.1.0 document.
pub fn render(result: &ScanResult) -> String {
    let doc = Sarif {
        schema: SARIF_SCHEMA,
        version: "2.1.0",
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "nearsc",
                    version: result.version,
                    information_uri: "https://github.com/vinibarbosabr/nearsc-auditor",
                    catalog: crate::rules::CATALOG
                        .iter()
                        .map(|entry| CatalogRule {
                            id: entry.id,
                            name: entry.title,
                            short_description: ShortDescription { text: entry.title },
                            help_uri: entry.refs.first().copied().unwrap_or("https://near.org"),
                        })
                        .collect(),
                },
            },
            results: result
                .findings
                .iter()
                .map(|finding| ResultEntry {
                    rule_id: finding.rule_id,
                    level: level_of(finding.severity),
                    message: Message {
                        text: finding.message.clone(),
                    },
                    locations: vec![Location {
                        physical_location: PhysicalLocation {
                            artifact_location: ArtifactLocation {
                                uri: finding.file.clone(),
                            },
                            region: Region {
                                start_line: finding.line,
                                start_column: finding.column,
                            },
                        },
                    }],
                    properties: ResultProperties {
                        severity: finding.severity.as_str(),
                        confidence: finding.confidence.as_str(),
                    },
                })
                .collect(),
        }],
    };
    serde_json::to_string_pretty(&doc).expect("SARIF serializes")
}

fn level_of(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}
