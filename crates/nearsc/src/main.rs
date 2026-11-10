use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use nearsc::engine;
use nearsc::finding::Severity;
use nearsc::rules::CATALOG;

#[derive(Parser)]
#[command(
    name = "nearsc",
    version,
    about = "Deterministic security scanner for NEAR smart contracts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan Rust sources for NEAR-specific vulnerability patterns
    Scan {
        /// Directory or .rs file to scan
        path: PathBuf,
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
        /// Exit with code 1 when a finding at or above this severity is present
        #[arg(long, value_enum)]
        fail_on: Option<SeverityArg>,
        /// Only report findings at or above this severity
        #[arg(long, value_enum)]
        min_severity: Option<SeverityArg>,
        /// Write the report to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show the rule catalog
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Print the knowledge-base index as JSON (checked in as data/index.json)
    KbIndex,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List all v0.1 rules with their status
    List,
    /// Show one rule's catalog entry
    Show {
        /// Rule id, e.g. NS002
        id: String,
    },
}

/// Severity names accepted by `--fail-on`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    match cli.command {
        Command::Scan {
            path,
            format,
            fail_on,
            min_severity,
            output,
        } => {
            if !path.exists() {
                anyhow::bail!("scan target not found: {}", path.display());
            }
            if path.is_file() {
                std::fs::File::open(&path).map_err(|err| {
                    anyhow::anyhow!("scan target unreadable: {}: {err}", path.display())
                })?;
            }

            let mut result = engine::scan_path(&path);
            if let Some(min) = min_severity {
                let min = Severity::from(min);
                result.findings.retain(|finding| finding.severity <= min);
                result.summary.recount(&result.findings);
            }
            if format == "json" {
                let rendered = serde_json::to_string_pretty(&result)?;
                match &output {
                    Some(file) => write_report(file, &rendered)?,
                    None => println!("{rendered}"),
                }
            } else {
                let mut rendered = String::new();
                print_text(&mut rendered, &result);
                match &output {
                    Some(file) => write_report(file, rendered.trim_end())?,
                    None => print!("{rendered}"),
                }
            }

            let gated = fail_on.is_some_and(|threshold| {
                let threshold = Severity::from(threshold);
                result
                    .findings
                    .iter()
                    .any(|finding| finding.severity <= threshold)
            });
            Ok(if gated { 1 } else { 0 })
        }
        Command::Rules { command } => match command {
            RulesCommand::List => {
                for entry in CATALOG {
                    println!(
                        "{:<8} {:<8} {:<9} {:<18} {}",
                        entry.id,
                        entry.severity.as_str(),
                        entry.confidence.as_str(),
                        entry.status,
                        entry.title
                    );
                }
                Ok(0)
            }
            RulesCommand::Show { id } => match CATALOG.iter().find(|entry| entry.id == id) {
                Some(entry) => {
                    println!("id:         {}", entry.id);
                    println!("title:      {}", entry.title);
                    println!("severity:   {}", entry.severity.as_str());
                    println!("confidence: {}", entry.confidence.as_str());
                    println!("status:     {}", entry.status);
                    match entry.matcher {
                        Some(matcher) => println!("matcher:    {matcher}"),
                        None => println!("matcher:    (planned)"),
                    }
                    println!("refs:");
                    for r in entry.refs {
                        println!("  - {r}");
                    }
                    println!("detection prose: docs/RULES.md");
                    Ok(0)
                }
                None => anyhow::bail!(
                    "unknown rule id: {}; valid ids: {}",
                    id,
                    CATALOG
                        .iter()
                        .map(|entry| entry.id)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            },
        },
        Command::KbIndex => {
            let index = nearsc::kb::build_index(&nearsc::kb::repo_data_dir())?;
            println!("{}", serde_json::to_string_pretty(&index)?);
            Ok(0)
        }
    }
}

fn write_report(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content)
        .map_err(|err| anyhow::anyhow!("cannot write {}: {err}", path.display()))
}

fn print_text(out: &mut String, result: &engine::ScanResult) {
    use std::fmt::Write;
    for finding in &result.findings {
        let _ = writeln!(
            out,
            "{:<8} {} {}:{} {}",
            finding.severity.as_str().to_uppercase(),
            finding.rule_id,
            finding.file,
            finding.line,
            finding.message
        );
    }
    for error in &result.parse_errors {
        let _ = writeln!(out, "parse-error {}: {}", error.file, error.message);
    }
    let summary = &result.summary;
    let _ = writeln!(
        out,
        "{} findings (critical {}, high {}, medium {}, low {}, info {})",
        result.findings.len(),
        summary.critical,
        summary.high,
        summary.medium,
        summary.low,
        summary.info
    );
}
