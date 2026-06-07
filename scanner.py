#!/usr/bin/env python3
"""
Pickle Bomb Detector - Scans for RCE vulnerabilities in ML training infrastructure

Usage:
    python scanner.py --help
    python scanner.py --target https://github.com/example/repo
    python scanner.py --targets targets.txt
    python scanner.py --clone-and-scan

Author: @Perfect370816 (X)
GitHub: https://github.com/Perfex-3437/pickle-bomb-detector
"""

import argparse
import subprocess
import json
import os
import shutil
import requests
from pathlib import Path
from datetime import datetime, timedelta
import sys

# ---------------------------
# Configuration
# ---------------------------
RAW_OUTPUT = "raw_results.json"
FILTERED_OUTPUT = "high_value_findings.json"
MAX_REPO_SIZE_MB = 1000
MAX_REPOS = 5000
DAYS_OLD = 30

# Dangerous code patterns
DANGEROUS_KEYWORDS = [
    "pickle", "deserializ", "yaml.load", "eval(", "exec(",
    "__reduce__", "joblib.load", "torch.load", "os.system",
    "subprocess.run", "subprocess.call", "popen", "spawn"
]

# Only report findings from these file paths
PATH_KEYWORDS = ["model", "load", "upload", "infer", "predict", "pipeline", "cache"]

# GitHub API search
SEARCH_QUERY = "topic:ai topic:machine-learning topic:llm topic:deep-learning"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def print_banner():
    """Print scanner banner"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║  🥒 PICKLE BOMB DETECTOR                                  ║
    ║  Finds RCE vulnerabilities in ML infrastructure           ║
    ║  Author: @Perfect370816 | GitHub: Perfex-3437              ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def get_fresh_targets():
    """Fetch fresh targets from GitHub API"""
    date_limit = (datetime.now() - timedelta(days=DAYS_OLD)).strftime("%Y-%m-%d")
    query = f"{SEARCH_QUERY} created:>{date_limit}"
    url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc&per_page={min(MAX_REPOS, 100)}"

    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        items = resp.json().get("items", [])
    except requests.exceptions.RequestException as e:
        print(f"⚠️  GitHub API error: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"⚠️  GitHub API response parse error: {e}")
        return []

    targets = []
    for repo in items:
        size_mb = repo.get("size", 0) / 1024
        if size_mb <= MAX_REPO_SIZE_MB:
            targets.append({
                "name": repo["full_name"],
                "clone_url": repo["clone_url"],
                "stars": repo["stargazers_count"],
                "size_mb": round(size_mb, 2)
            })
    return targets


def update_targets(target_url=None):
    """Clone or update targets folder"""
    targets_dir = Path("targets")
    if targets_dir.exists():
        shutil.rmtree(targets_dir)
    targets_dir.mkdir(exist_ok=True)

    if target_url:
        # Single target mode
        targets = [{"name": target_url, "clone_url": target_url, "size_mb": 0}]
    else:
        # Fresh targets from GitHub
        targets = get_fresh_targets()
        if not targets:
            print("⚠️  No fresh AI/ML repos found. Using fallback repos.")
            targets = [
                {"name": "BerriAI/litellm", "clone_url": "https://github.com/BerriAI/litellm.git"},
                {"name": "langgenius/dify", "clone_url": "https://github.com/langgenius/dify.git"},
                {"name": "open-webui/open-webui", "clone_url": "https://github.com/open-webui/open-webui.git"}
            ]

    for t in targets:
        repo_path = targets_dir / t["name"].split("/")[-1]
        print(f"📥 Cloning {t['name']} ({t.get('size_mb', '?')} MB) ...")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", t["clone_url"], str(repo_path)],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                print(f"⚠️  Failed to clone {t['name']}: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            print(f"⚠️  Clone timeout for {t['name']}")
        except Exception as e:
            print(f"⚠️  Error cloning {t['name']}: {e}")
    return targets


def run_semgrep():
    """Run semgrep scan on targets"""
    targets_dir = Path("targets")
    if not targets_dir.exists() or not any(targets_dir.iterdir()):
        print("❌ No repos to scan.")
        return False

    print("🔍 Running semgrep scan...")
    cmd = [
        "semgrep", "scan",
        "--config", "p/python",
        "--config", "p/security-audit",
        "--max-memory", "512",
        "--json",
        "--output", RAW_OUTPUT,
        str(targets_dir)
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if result.returncode != 0:
            print(f"⚠️  Semgrep warning: {result.stderr[:500]}")
        return True
    except subprocess.TimeoutExpired:
        print("❌ Semgrep scan timed out")
        return False
    except FileNotFoundError:
        print("❌ semgrep not found. Install with: pip install semgrep")
        return False
    except Exception as e:
        print(f"❌ Semgrep error: {e}")
        return False


def filter_findings():
    """Filter semgrep findings for high-value targets"""
    if not Path(RAW_OUTPUT).exists():
        print("⚠️  No raw results found.")
        return []

    try:
        with open(RAW_OUTPUT) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"⚠️  Error parsing {RAW_OUTPUT}: {e}")
        return []

    filtered = []
    for res in data.get("results", []):
        check_id = res.get("check_id", "").lower()
        code = res.get("extra", {}).get("lines", "").lower()
        path = res.get("path", "").lower()

        # Danger check
        if not any(k.lower() in (code + check_id) for k in DANGEROUS_KEYWORDS):
            continue

        # Path filter
        if not any(k in path for k in PATH_KEYWORDS):
            continue

        # Extract repo name
        parts = Path(path).parts
        repo = parts[1] if len(parts) > 1 else "unknown"

        filtered.append({
            "repo": repo,
            "file": path,
            "line": res.get("start", {}).get("line"),
            "rule": check_id,
            "code_snippet": res.get("extra", {}).get("lines", "").strip()[:200],
            "severity": res.get("extra", {}).get("severity", "WARNING")
        })

    try:
        with open(FILTERED_OUTPUT, "w") as f:
            json.dump(filtered, f, indent=2)
        print(f"✅ Filtered {len(filtered)} high-value findings → {FILTERED_OUTPUT}")
    except Exception as e:
        print(f"⚠️  Error writing {FILTERED_OUTPUT}: {e}")

    return filtered


def notify(findings):
    """Notify about findings (placeholder for notify.py)"""
    if findings:
        print(f"🚨 {len(findings)} high-value findings detected!")
        print("📧 Notification would be sent (implement in notify.py)")
    else:
        print("✅ No dangerous patterns found tonight.")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Pickle Bomb Detector - Scan for RCE vulnerabilities in ML code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --help                    Show this help
  python scanner.py --target https://github.com/example/repo  Scan single repo
  python scanner.py --targets targets.txt     Scan repos from file
  python scanner.py --clone-and-scan          Clone fresh targets and scan
  python scanner.py                          Clone fresh targets and scan (default)
        """
    )
    
    parser.add_argument(
        "--target",
        type=str,
        help="Single repository URL to scan"
    )
    
    parser.add_argument(
        "--targets",
        type=str,
        help="Text file with repository URLs (one per line)"
    )
    
    parser.add_argument(
        "--clone-and-scan",
        action="store_true",
        help="Clone fresh AI/ML repos from GitHub and scan"
    )
    
    parser.add_argument(
        "--skip-clone",
        action="store_true",
        help="Skip cloning, only scan existing targets/ directory"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="high_value_findings.json",
        help="Output file for filtered findings (default: high_value_findings.json)"
    )
    
    args = parser.parse_args()

    print_banner()
    print(f"🕒 Started: {datetime.now().isoformat()}")

    # Step 1: Setup targets
    if args.skip_clone:
        print("⏭️  Skipping clone, using existing targets/")
    elif args.target:
        print(f"🎯 Single target mode: {args.target}")
        update_targets(args.target)
    elif args.targets:
        print(f"📋 Reading targets from: {args.targets}")
        with open(args.targets) as f:
            for line in f:
                line = line.strip()
                if line:
                    update_targets(line)
    else:
        print("🌱 Clone and scan mode: Fetching fresh AI/ML repos...")
        update_targets()

    # Step 2: Run scan
    if not run_semgrep():
        print("❌ Scan failed. Exiting.")
        sys.exit(1)

    # Step 3: Filter findings
    findings = filter_findings()

    # Step 4: Notify
    notify(findings)

    # Log the run
    try:
        with open("scan_log.txt", "a") as log:
            log.write(f"{datetime.now().isoformat()} - {len(findings)} findings\n")
    except Exception as e:
        print(f"⚠️  Error writing scan log: {e}")

    print(f"✅ Scan complete. {len(findings)} high-value findings saved to {args.output}")


if __name__ == "__main__":
    main()