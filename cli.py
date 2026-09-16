#!/usr/bin/env python3
"""Command line entry point.

Usage:
    python cli.py path/to/email.eml
    python cli.py path/to/email.eml --html report.html
"""

import argparse
import sys

from analyser.parser import load_email, get_body_text_and_html
from analyser.scoring import run_checks, risk_category
from analyser.report import print_console_report, write_html_report
from analyser import reputation


def main():
    parser = argparse.ArgumentParser(description="Analyse a .eml file for phishing indicators.")
    parser.add_argument("eml_file", help="Path to the .eml file to check")
    parser.add_argument("--html", metavar="OUTPUT_FILE", help="Also write an HTML report to this path")
    args = parser.parse_args()

    try:
        msg = load_email(args.eml_file)
    except FileNotFoundError:
        print(f"Could not find {args.eml_file}", file=sys.stderr)
        sys.exit(1)

    text_body, html_body = get_body_text_and_html(msg)
    findings, score = run_checks(msg, text_body, html_body)
    category = risk_category(score)

    subject = msg.get("Subject", "(no subject)")
    sender = msg.get("From", "(unknown sender)")

    print_console_report(subject, sender, findings, score, category)

    if not reputation.is_configured():
        print("\n(VirusTotal lookups skipped, no VT_API_KEY environment variable set)")

    if args.html:
        write_html_report(args.html, subject, sender, findings, score, category)
        print(f"\nHTML report written to {args.html}")


if __name__ == "__main__":
    main()
