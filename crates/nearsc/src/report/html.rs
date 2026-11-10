//! Self-contained HTML report.
//!
//! Single file, inline `<style>`, no JavaScript, no external requests. Every
//! byte derived from findings is HTML-escaped: scanned source is untrusted
//! data and must never become markup. Byte-stable for the same input: no
//! timestamps, findings arrive sorted.

use std::fmt::Write as _;

use crate::engine::ScanResult;
use crate::finding::Severity;

/// Render the scan envelope as a standalone HTML document.
pub fn render(result: &ScanResult) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>nearsc scan: {}</title>\n<style>",
        escape(&result.target)
    );
    out.push_str(STYLE);
    let _ = write!(
        out,
        "</style>\n</head>\n<body>\n<header>\n<h1>nearsc scan report</h1>\n<p class=\"meta\">target: <code>{}</code> &middot; version: {}</p>\n</header>\n",
        escape(&result.target),
        escape(result.version),
    );

    let _ = write!(
        out,
        "<section class=\"summary\">\n<h2>Summary</h2>\n{}\n</section>\n",
        summary_cards(result)
    );

    out.push_str("<section class=\"findings\">\n<h2>Findings (");
    let _ = writeln!(out, "{}</h2>", result.findings.len());
    for finding in &result.findings {
        let _ = write!(
            out,
            "<article class=\"finding severity-{s}\">\n<div class=\"finding-head\">\n<span class=\"badge\">{s}</span>\n<span class=\"rule\">{id}</span>\n<span class=\"loc\"><code>{file}:{line}</code></span>\n</div>\n<p class=\"message\">{message}</p>\n<pre class=\"snippet\"><code>{snippet}</code></pre>\n<ul class=\"refs\">",
            s = escape(finding.severity.as_str()),
            id = escape(finding.rule_id),
            file = escape(&finding.file),
            line = finding.line,
            message = escape(&finding.message),
            snippet = escape(&finding.snippet),
        );
        for r in finding.refs {
            let _ = write!(
                out,
                "<li><a href=\"{r}\" rel=\"noopener noreferrer\">{r}</a></li>",
                r = escape(r),
            );
        }
        out.push_str("</ul>\n</article>\n");
    }
    if result.findings.is_empty() {
        out.push_str("<p class=\"clean\">No findings.</p>\n");
    }
    out.push_str("</section>\n");

    if !result.parse_errors.is_empty() {
        out.push_str("<section class=\"parse-errors\">\n<h2>Parse errors</h2>\n<ul>\n");
        for error in &result.parse_errors {
            let _ = write!(
                out,
                "<li><code>{}</code>: {}</li>",
                escape(&error.file),
                escape(&error.message)
            );
            out.push('\n');
        }
        out.push_str("</ul>\n</section>\n");
    }

    out.push_str(
        "<footer>\n<p>Static analysis output. It is not a substitute for a manual audit; confirm every finding before acting on it. Generated deterministically by nearsc; the same input yields the same report on any machine.</p>\n</footer>\n</body>\n</html>\n",
    );
    out
}

fn summary_cards(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("<div class=\"cards\">\n");
    for (severity, count) in [
        (Severity::Critical, result.summary.critical),
        (Severity::High, result.summary.high),
        (Severity::Medium, result.summary.medium),
        (Severity::Low, result.summary.low),
        (Severity::Info, result.summary.info),
    ] {
        let _ = write!(
            out,
            "<div class=\"card severity-{s}\">\n<span class=\"count\">{n}</span>\n<span class=\"label\">{s}</span>\n</div>\n",
            s = severity.as_str(),
            n = count,
        );
    }
    out.push_str("</div>\n");
    out
}

/// Escape sensitive `&<>"'` characters so scanned source can never become
/// markup.
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

const STYLE: &str = r#"
:root {
  font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background: #16181d;
  color: #e7e9ee;
}
body { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.1rem; margin: 0 0 12px; color: #9aa3b2; text-transform: uppercase; letter-spacing: 0.06em; }
.meta { color: #9aa3b2; margin: 0; font-size: 0.9rem; }
.meta code { background: #23262d; padding: 2px 6px; border-radius: 4px; }
section { margin: 28px 0; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; }
.card { background: #23262d; border-radius: 10px; padding: 12px 18px; min-width: 96px; text-align: center; }
.count { display: block; font-size: 1.6rem; font-weight: 700; }
.label { color: #9aa3b2; font-size: 0.85rem; }
.severity-critical .count, .severity-critical .badge { color: #ff5c5c; }
.severity-high .count, .severity-high .badge { color: #ff8a4c; }
.severity-medium .count, .severity-medium .badge { color: #ffd166; }
.severity-low .count, .severity-low .badge { color: #6fc3ff; }
.severity-info .count, .severity-info .badge { color: #a2d6a2; }
.finding { background: #1d2026; border: 1px solid #2a2e37; border-radius: 10px; padding: 12px 16px; margin: 12px 0; }
.finding-head { display: flex; align-items: center; gap: 10px; }
.badge { font-weight: 700; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.08em; }
.rule { font-family: ui-monospace, monospace; }
.loc code { font-family: ui-monospace, monospace; color: #9aa3b2; }
.message { margin: 10px 0 8px; }
.snippet { background: #14161a; border-radius: 8px; padding: 10px 12px; overflow-x: auto; margin: 0 0 8px; }
.snippet code { font-family: ui-monospace, monospace; font-size: 0.9rem; }
.refs { list-style: none; padding: 0; margin: 0; }
.refs li { margin: 2px 0; }
.refs a { color: #6fc3ff; text-decoration: none; word-break: break-all; }
.parse-errors code { background: #23262d; padding: 2px 6px; border-radius: 4px; }
footer { border-top: 1px solid #2a2e37; margin-top: 32px; padding-top: 12px; color: #9aa3b2; font-size: 0.85rem; }
"#;
