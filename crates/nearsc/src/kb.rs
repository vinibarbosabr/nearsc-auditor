use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One knowledge-base entry as stored in `data/index.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: String,
    pub kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub year: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_counts: Option<Value>,
    pub tags: Vec<String>,
    pub path: String,
    pub summary: String,
    pub source: String,
    pub retrieved: String,
    pub confidence: String,
}

/// Build the index from a repository `data/` directory.
///
/// The frontmatter subset parsed here is intentionally small: single-line
/// `key: value` pairs, inline `[a, b]` arrays, and inline JSON maps for
/// `severity_counts`.
pub fn build_index(data_dir: &Path) -> anyhow::Result<Vec<IndexEntry>> {
    let mut entries = Vec::new();
    for kind_dir in ["patterns", "audits", "postmortems"] {
        let dir = data_dir.join(kind_dir);
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|entry| entry.ok())
        {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let fields = parse_frontmatter(&text)
                .with_context(|| format!("parsing frontmatter of {}", path.display()))?;
            entries.push(to_entry(kind_dir, &path, &fields)?);
        }
    }
    entries.sort_by(|a, b| (a.kind.as_str(), a.id.as_str()).cmp(&(b.kind.as_str(), b.id.as_str())));
    Ok(entries)
}

/// Case-insensitive substring search across title, project, tags, and summary.
pub fn search<'a>(entries: &'a [IndexEntry], query: &str) -> Vec<&'a IndexEntry> {
    let query = query.to_lowercase();
    entries
        .iter()
        .filter(|entry| {
            entry.title.to_lowercase().contains(&query)
                || entry.summary.to_lowercase().contains(&query)
                || entry
                    .project
                    .as_deref()
                    .is_some_and(|project| project.to_lowercase().contains(&query))
                || entry
                    .tags
                    .iter()
                    .any(|tag| tag.to_lowercase().contains(&query))
        })
        .collect()
}

fn to_entry(
    kind_dir: &str,
    path: &Path,
    fields: &BTreeMap<String, String>,
) -> anyhow::Result<IndexEntry> {
    let required = |key: &str| -> anyhow::Result<String> {
        fields
            .get(key)
            .cloned()
            .with_context(|| format!("missing frontmatter key `{key}`"))
    };
    let optional = |key: &str| -> Option<String> { fields.get(key).cloned() };
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("non-utf8 file name")?;
    let id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("non-utf8 file name")?
        .to_string();
    let kind = match kind_dir {
        "patterns" => "pattern",
        "audits" => "audit",
        _ => "postmortem",
    }
    .to_string();
    Ok(IndexEntry {
        id,
        kind,
        title: required("title")?,
        project: optional("project"),
        year: optional("year").and_then(|year| year.parse().ok()),
        rule: optional("rule"),
        severity: optional("severity"),
        severity_counts: optional("severity_counts")
            .and_then(|value| serde_json::from_str(&value).ok()),
        tags: optional("tags")
            .map(|tags| {
                tags.trim_start_matches('[')
                    .trim_end_matches(']')
                    .split(',')
                    .map(|tag| tag.trim().trim_matches('"').to_string())
                    .filter(|tag| !tag.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        path: format!("data/{kind_dir}/{file_name}"),
        summary: required("summary")?,
        source: required("source")?,
        retrieved: required("retrieved")?,
        confidence: required("confidence")?,
    })
}

fn parse_frontmatter(text: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        anyhow::bail!("file does not start with frontmatter");
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        if line == "---" {
            return Ok(fields);
        }
        if let Some((key, value)) = line.split_once(':') {
            fields.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }
    anyhow::bail!("unterminated frontmatter")
}

/// The repo `data/` directory, resolved from the crate manifest at compile time.
pub fn repo_data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data")
}
