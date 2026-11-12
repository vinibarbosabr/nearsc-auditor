use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use nearsc::engine;
use nearsc::finding::{Confidence, Severity};
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
        #[arg(long, default_value = "text", value_parser = ["text", "json", "sarif", "html"])]
        format: String,
        /// Exit with code 1 when a finding at or above this severity is present
        #[arg(long, value_enum)]
        fail_on: Option<SeverityArg>,
        /// Only report findings at or above this severity
        #[arg(long, value_enum)]
        min_severity: Option<SeverityArg>,
        /// Only report findings at or above this confidence
        #[arg(long, value_enum)]
        min_confidence: Option<ConfidenceArg>,
        /// Comma-separated rule ids to run (e.g. ns004,ns010); default runs all
        #[arg(long)]
        only: Option<String>,
        /// Write the report to this file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Show the rule catalog
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Fetch a contract account's deployment info over public RPC and check
    /// it against the audited-build registry
    Contract {
        /// NEAR account id, e.g. wrap.near
        account_id: String,
        /// Network to query (default mainnet)
        #[arg(long, value_enum, default_value = "mainnet")]
        network: NetworkArg,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Print the knowledge-base index as JSON (checked in as data/index.json)
    KbIndex,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List all v0.1 rules with their status
    List {
        /// Output format
        #[arg(long, default_value = "text", value_parser = ["text", "json"])]
        format: String,
    },
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

/// Networks accepted by `contract --network`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
}

/// Confidence levels accepted by `--min-confidence`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ConfidenceArg {
    Spec,
    Heuristic,
}

impl From<ConfidenceArg> for Confidence {
    fn from(value: ConfidenceArg) -> Self {
        match value {
            ConfidenceArg::Spec => Confidence::Spec,
            ConfidenceArg::Heuristic => Confidence::Heuristic,
        }
    }
}

impl From<NetworkArg> for nearsc::rpc::Network {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => nearsc::rpc::Network::Mainnet,
            NetworkArg::Testnet => nearsc::rpc::Network::Testnet,
        }
    }
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

/// Parse `--only ns004,ns010` into individual ids, lowercased for matching.
fn parse_only_ids(value: &str) -> Result<Vec<String>, String> {
    let ids: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(|id| id.to_ascii_lowercase())
        .collect();
    if ids.is_empty() {
        return Err("empty --only list".to_string());
    }
    Ok(ids)
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
            min_confidence,
            only,
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

            if let Some(only) = only.as_deref() {
                let requested = parse_only_ids(only).map_err(anyhow::Error::msg)?;
                let catalog_ids: Vec<&str> = CATALOG.iter().map(|entry| entry.id).collect();
                for id in &requested {
                    if !catalog_ids
                        .iter()
                        .any(|catalog_id| catalog_id.eq_ignore_ascii_case(id))
                    {
                        anyhow::bail!(
                            "unknown rule id: {}; valid ids: {}",
                            id,
                            catalog_ids.join(", ")
                        );
                    }
                }
                let result = engine::scan_path_only(&path, &requested);
                return render_and_gate(
                    result, format, fail_on, min_severity, min_confidence, output,
                );
            }

            let result = engine::scan_path(&path);
            render_and_gate(result, format, fail_on, min_severity, min_confidence, output)
        }
        Command::Rules { command } => match command {
            RulesCommand::List { format } => {
                if format == "json" {
                    println!("{}", serde_json::to_string_pretty(&CATALOG)?);
                } else {
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
            let data_dir = nearsc::kb::repo_data_dir();
            let has_kb_dir = ["patterns", "audits", "postmortems"]
                .iter()
                .any(|dir| data_dir.join(dir).is_dir());
            if !has_kb_dir {
                anyhow::bail!(
                    "knowledge-base data not found at {}; kb-index requires a repository checkout",
                    data_dir.display()
                );
            }
            let index = nearsc::kb::build_index(&data_dir)?;
            println!("{}", serde_json::to_string_pretty(&index)?);
            Ok(0)
        }
        Command::Contract {
            account_id,
            network,
            json,
        } => {
            let info = nearsc::rpc::fetch_contract_info(&account_id, network.into())
                .map_err(|err| anyhow::anyhow!("contract lookup failed: {err:#}"))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("account:        {}", info.account_id);
                println!("network:        {}", info.network);
                println!("exists:         {}", info.exists);
                println!("has code:       {}", info.has_code);
                match &info.code_hash {
                    Some(hash) => println!("code hash:      {hash}"),
                    None => println!("code hash:      (none)"),
                }
                if let Some(balance) = &info.balance_yocto {
                    println!("balance yocto:  {balance}");
                }
                if let Some(storage) = &info.storage_usage {
                    println!("storage usage:  {storage}");
                }
                match info.registry_match {
                    Some(true) => println!("registry:       MATCH (audited code hash)"),
                    Some(false) => {
                        println!("registry:       deployed code differs from the audited build")
                    }
                    None => println!("registry:       account not in the audited registry"),
                }
                for audit in &info.known_audits {
                    println!("audit:          {} ({})", audit.title, audit.source);
                }
            }
            Ok(0)
        }
    }
}

fn write_report(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content)
        .map_err(|err| anyhow::anyhow!("cannot write {}: {err}", path.display()))
}

/// Render a finished scan (text, json, sarif, or html), then apply the
/// `--fail-on` gate.
fn render_and_gate(
    mut result: engine::ScanResult,
    format: String,
    fail_on: Option<SeverityArg>,
    min_severity: Option<SeverityArg>,
    min_confidence: Option<ConfidenceArg>,
    output: Option<PathBuf>,
) -> anyhow::Result<u8> {
    if let Some(min) = min_severity {
        let min = Severity::from(min);
        engine::filter_min_severity(&mut result, min);
    }
    if let Some(min) = min_confidence {
        let min = Confidence::from(min);
        // Confidence ordering: spec > heuristic. Keep findings whose
        // confidence is at or above the requested floor.
        result.findings.retain(|finding| match (min, finding.confidence) {
            (Confidence::Spec, Confidence::Spec) => true,
            (Confidence::Spec, Confidence::Heuristic) => false,
            (Confidence::Heuristic, _) => true,
        });
        result.summary.recount(&result.findings);
    }
    let rendered: anyhow::Result<String> = match format.as_str() {
        "json" => nearsc::report::render_json(&result),
        "sarif" => nearsc::report::render_sarif(&result),
        "html" => nearsc::report::render_html(&result),
        _ => {
            let mut rendered = String::new();
            nearsc::report::render_text(&mut rendered, &result);
            let heuristic = result
                .findings
                .iter()
                .filter(|finding| finding.confidence == Confidence::Heuristic)
                .count();
            if heuristic > 0 {
                rendered.push_str(&format!(
                    "disclaimer: {heuristic} of {} findings are heuristic-confidence review hints; expect false positives and confirm each one by hand\n",
                    result.findings.len()
                ));
            }
            Ok(rendered.trim_end().to_string())
        }
    };
    let rendered = rendered?;
    match &output {
        Some(file) => write_report(file, &rendered)?,
        None => println!("{rendered}"),
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
