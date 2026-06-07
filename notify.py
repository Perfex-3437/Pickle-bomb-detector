#!/usr/bin/env python3
"""
Notification script for Pickle Bomb Detector
Sends alerts when high-value findings are detected
"""

import json
from pathlib import Path

FILTERED_OUTPUT = "high_value_findings.json"


def send_notification(findings):
    """Send notification about findings"""
    if not findings:
        return

    message = f"🚨 Pickle Bomb Detector Alert\n\n"
    message += f"Found {len(findings)} high-value vulnerabilities:\n\n"

    for f in findings[:5]:  # Limit to first 5
        message += f"• {f['repo']}/{f['file']}:{f['line']}\n"
        message += f"  Rule: {f['rule']}\n"
        message += f"  Snippet: {f['code_snippet'][:100]}...\n\n"

    if len(findings) > 5:
        message += f"... and {len(findings) - 5} more.\n\n"

    message += "Full report: high_value_findings.json"

    # Print to console (replace with actual notification)
    print(message)

    # TODO: Add your notification method here
    # Examples:
    # - Send to Discord webhook
    # - Send email
    # - Post to Slack
    # - Send Telegram message


if __name__ == "__main__":
    if Path(FILTERED_OUTPUT).exists():
        with open(FILTERED_OUTPUT) as f:
            findings = json.load(f)
        send_notification(findings)
    else:
        print("No findings file found.")