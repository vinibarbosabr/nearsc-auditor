//! PoC scaffold generation for the `nearsc_poc_scaffold` tool.
//!
//! Pure templating: no network, no timestamps, nothing written to disk. The
//! min-severity filter shared with the CLI lives in the `nearsc` crate.

use std::path::Path;

use nearsc::rules::RuleMeta;
use serde::Serialize;

/// A generated PoC: files to create (paths relative to the agent's project)
/// and plain-language instructions. Content only; nothing is written to disk.
#[derive(Serialize)]
pub struct PocScaffold {
    pub rule: &'static str,
    pub title: &'static str,
    pub files: std::collections::BTreeMap<String, String>,
    pub instructions: String,
}

/// Deterministic workspaces-rs skeleton for one finding. No network, no
/// timestamps: the same inputs produce the same bytes.
pub fn poc_scaffold(
    rule: &RuleMeta,
    contract_path: &Path,
    pattern_body: Option<&str>,
) -> PocScaffold {
    let contract = contract_path.display().to_string();
    let crate_name = format!("nearsc-poc-{}", rule.id.to_ascii_lowercase());

    let mut cargo_toml = String::new();
    cargo_toml.push_str("# Dev-only harness: the PoC never deploys to mainnet and never signs.\n");
    cargo_toml.push_str("# Build the target contract first:\n");
    cargo_toml.push_str(
        "#   cargo build -p <target-contract> --target wasm32-unknown-unknown --release\n",
    );
    cargo_toml.push_str(&format!(
        "\n[dev-dependencies]\nnear-workspaces = \"0.18\"\nanyhow = \"1\"\n\n[[test]]\nname = \"poc_{}\"\nharness = true\n",
        rule.id.to_ascii_lowercase()
    ));

    let pattern_note = match pattern_body {
        Some(body) => {
            let vuln = body
                .split("## Vulnerable pattern")
                .nth(1)
                .and_then(|rest| rest.split("## Fixed pattern").next())
                .unwrap_or("(see the pattern doc)")
                .trim();
            let fixed = body
                .split("## Fixed pattern")
                .nth(1)
                .map(|rest| rest.trim())
                .unwrap_or("(see the pattern doc)");
            format!("## From the pattern doc ({})\n\n### Vulnerable\n\n{vuln}\n\n### Fixed\n\n{fixed}\n", rule.id)
        }
        None => format!(
            "## Pattern doc\n\nNot embedded for {}; see docs/RULES.md.\n",
            rule.id
        ),
    };

    let mut test_rs = String::new();
    test_rs.push_str(&format!(
        "// PoC scaffold for {} ({}): prove the finding is exploitable before fixing.\n\
         // Safety: testnet only (near_workspaces::sandbox()), no mainnet, no real funds.\n",
        rule.id, rule.title
    ));
    test_rs.push_str("use near_workspaces::{sandbox, types::NearToken};\n\n");
    test_rs.push_str(&format!(
        "const CONTRACT_WASM: &str = \"{contract}\"; // TODO: point at the built wasm artifact\n\n#[tokio::test]\nasync fn poc_{}",
        rule.id.to_ascii_lowercase()
    ));
    test_rs.push_str(
        "() -> anyhow::Result<()> {\n    let worker = sandbox().await?;\n    let contract = worker.dev_deploy(&std::fs::read(CONTRACT_WASM)?).await?;\n\n\
         // TODO 1: call the method the rule flagged, the way an attacker would.\n\
         // TODO 2: assert the harmful state transition succeeded (pre-fix) or was rejected (post-fix).\n\
         // TODO 3: apply the fix from the pattern doc, rebuild, and flip the assertion.\n\n\
         anyhow::bail!(\"scaffold: fill in the TODOs before running\")\n}\n",
    );

    let mut instructions = String::new();
    instructions.push_str(&format!(
        "This is a scaffold for {} ({}), not a runnable test.\n\
         1. Build the contract at `{contract}` to wasm32-unknown-unknown and point CONTRACT_WASM at the artifact.\n\
         2. Fill the TODOs: reproduce the flagged behavior, assert the impact, then apply the fix and assert it is gone.\n\
         3. Run on the local sandbox only: `cargo test --test poc_{}`. Never deploy or sign on mainnet.\n\
         4. Finding references:\n",
        rule.id, rule.title, rule.id.to_ascii_lowercase()
    ));
    for reference in rule.refs {
        instructions.push_str(&format!("   - {reference}\n"));
    }

    let mut files = std::collections::BTreeMap::new();
    files.insert(format!("{crate_name}/Cargo.toml"), cargo_toml);
    files.insert(
        format!("{crate_name}/tests/poc_{}.rs", rule.id.to_ascii_lowercase()),
        test_rs,
    );
    files.insert(
        format!("{crate_name}/pattern-{}.md", rule.id.to_ascii_lowercase()),
        pattern_note,
    );

    PocScaffold {
        rule: rule.id,
        title: rule.title,
        files,
        instructions,
    }
}
