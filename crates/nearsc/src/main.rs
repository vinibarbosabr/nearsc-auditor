use std::path::PathBuf;

use clap::{Parser, Subcommand};

use nearsc::engine;

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
    },
    /// Print the knowledge-base index as JSON (checked in as data/index.json)
    KbIndex,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Scan { path, format } => {
            let result = engine::scan_path(&path);
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_text(&result);
            }
            Ok(())
        }
        Command::KbIndex => {
            let index = nearsc::kb::build_index(&nearsc::kb::repo_data_dir())?;
            println!("{}", serde_json::to_string_pretty(&index)?);
            Ok(())
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
