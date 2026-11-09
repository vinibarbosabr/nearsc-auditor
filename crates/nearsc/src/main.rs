use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use nearsc::engine;
use nearsc::finding::Severity;

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
    },
    /// Print the knowledge-base index as JSON (checked in as data/index.json)
    KbIndex,
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
        } => {
            if !path.exists() {
                anyhow::bail!("scan target not found: {}", path.display());
            }
            if path.is_file() {
                std::fs::File::open(&path).map_err(|err| {
                    anyhow::anyhow!("scan target unreadable: {}: {err}", path.display())
                })?;
            }

            let result = engine::scan_path(&path);
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_text(&result);
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
        Command::KbIndex => {
            let index = nearsc::kb::build_index(&nearsc::kb::repo_data_dir())?;
            println!("{}", serde_json::to_string_pretty(&index)?);
            Ok(0)
        }
    }
}

fn print_text(result: &engine::ScanResult) {
    for finding in &result.findings {
        println!(
            "{:<8} {} {}:{} {}",
            finding.severity.as_str().to_uppercase(),
            finding.rule_id,
            finding.file,
            finding.line,
            finding.message
        );
    }
    for error in &result.parse_errors {
        println!("parse-error {}: {}", error.file, error.message);
    }
    let summary = &result.summary;
    println!(
        "{} findings (critical {}, high {}, medium {}, low {}, info {})",
        result.findings.len(),
        summary.critical,
        summary.high,
        summary.medium,
        summary.low,
        summary.info
    );
}
