#!/usr/bin/env python3
import argparse
import subprocess
import re
from pathlib import Path
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description="Setup NEAR Smart Contract Audit")
    parser.add_argument("--project", required=True, help="Project name")
    parser.add_argument("--repo", required=True, help="GitHub repository URL")
    parser.add_argument("--bug-bounty", required=True, help="Bug bounty program URL")
    parser.add_argument(
        "--root", default="~/vinib-audits/nearsc", help="Root audits directory"
    )
    args = parser.parse_args()

    project = args.project
    repo_url = args.repo.rstrip("/")
    bug_bounty = args.bug_bounty
    root = Path(args.root).expanduser()

    audit_dir = root / f"audit-{project}"
    code_dir = audit_dir / "code"
    template_path = Path(
        "~/nearsc-auditor/resources/templates/report-template.md"
    ).expanduser()
    report_path = audit_dir / "REPORT.md"

    print(f"\n=== Setting up audit for: {project} ===\n")

    # Create audit directory
    audit_dir.mkdir(parents=True, exist_ok=True)

    # Clone repository
    print("Cloning repository into audit folder...")
    if not code_dir.exists():
        subprocess.run(["git", "clone", repo_url, str(code_dir)], check=True)
    else:
        print(f"⚠️  {code_dir} already exists. Skipping clone.")

    # Get dynamic values
    branch = subprocess.check_output(
        ["git", "-C", str(code_dir), "branch", "--show-current"], text=True
    ).strip()

    commit = subprocess.check_output(
        ["git", "-C", str(code_dir), "rev-parse", "--short", "HEAD"], text=True
    ).strip()

    date = datetime.now().strftime("%Y-%m-%d")

    # Copy template
    content = template_path.read_text()

    # === Replace Executive Summary fields ===
    replacements = {
        r"^\*\*Project:\*\*.*": f"**Project:** {project}",
        r"^\*\*Repository:\*\*.*": f"**Repository:** {repo_url}",
        r"^\*\*Commit:\*\*.*": f"**Commit:** {commit}",
        r"^\*\*Branch:\*\*.*": f"**Branch:** {branch}",
        r"^\*\*Date:\*\*.*": f"**Date:** {date}",
        r"^\*\*Auditor:\*\*.*": "**Auditor:** Vini B",
        r"^\*\*Bug Bounty Program:\*\*.*": f"**Bug Bounty Program:** {bug_bounty}",
        r"^\*\*Contract Address:\*\*.*": "**Contract Address:** ",
    }

    for pattern, replacement in replacements.items():
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

    report_path.write_text(content)

    # Success message + show the updated REPORT.md
    print("\n✅ Audit environment created successfully!")
    print(f"📁 Audit folder: {audit_dir}")
    print(f"📄 REPORT.md has been updated with the executive summary.\n")

    # Show the Executive Summary section
    print("=== REPORT.md - Executive Summary ===\n")
    with open(report_path) as f:
        lines = f.readlines()
        in_summary = False
        for line in lines:
            if "## 1. Executive Summary" in line:
                in_summary = True
            if in_summary:
                print(line, end="")
            if in_summary and line.strip().startswith("### Abstract"):
                break
    print("\n=== END ===")


if __name__ == "__main__":
    main()
