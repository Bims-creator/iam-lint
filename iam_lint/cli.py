"""
Command-line entry point for iam-lint.

Usage:
    iam-lint scan policy.json
    iam-lint scan policy.json --format json
"""

import argparse
import json
import sys

from .scanner import lint_policy


def load_policy(path):
    with open(path) as f:
        return json.load(f)


def format_human(findings):
    """
    Turn a list of finding dicts (see scanner.py for the shape) into a
    human-readable multi-line string, one finding per line.

    - If findings is empty, return "No issues found."
    - Otherwise, return one line per finding, formatted so a reader can
      see the rule name, which statement it came from, and the message.
      Suggested shape per line:
          [RULE_NAME] statement 0: the message text
    """
    if not findings:
        return "No issues found."

    lines = []
    for finding in findings:
        rule_name = finding.get("rule", "UNKNOWN_RULE")
        statement_index = finding.get("statement_index", "UNKNOWN_INDEX")
        message = finding.get("message", "No message provided.")
        severity = finding.get("severity", "UNKNOWN_SEVERITY")
        lines.append(f"[{severity.upper()}] [{rule_name}] statement {statement_index}: {message}")

    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="iam-lint", description="Static analysis for AWS IAM policy documents.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan an IAM policy JSON file.")
    scan_parser.add_argument("policy_file", help="Path to the IAM policy JSON file.")
    scan_parser.add_argument("--format", choices=["human", "json"], default="human")

    args = parser.parse_args(argv)

    policy = load_policy(args.policy_file)
    findings = lint_policy(policy)

    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        print(format_human(findings))

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
