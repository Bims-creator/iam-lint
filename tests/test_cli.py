import json
import subprocess
import sys

from iam_lint.cli import format_human


def test_format_human_no_findings():
    assert format_human([]) == "No issues found."


def test_format_human_single_finding():
    findings = [
        {
            "statement_index": 0,
            "rule": "WILDCARD_ACTION",
            "severity": "high",
            "message": "Action includes \"*\", granting every action.",
        }
    ]
    output = format_human(findings)
    assert "WILDCARD_ACTION" in output
    assert "HIGH" in output
    assert "statement 0" in output
    assert "Action includes" in output


def test_format_human_multiple_findings_one_per_line():
    findings = [
        {"statement_index": 0, "rule": "WILDCARD_ACTION", "severity": "high", "message": "msg1"},
        {"statement_index": 1, "rule": "WILDCARD_RESOURCE", "severity": "high", "message": "msg2"},
    ]
    output = format_human(findings)
    lines = output.strip().split("\n")
    assert len(lines) == 2
    assert "WILDCARD_ACTION" in lines[0]
    assert "WILDCARD_RESOURCE" in lines[1]


def test_cli_json_output_and_exit_code(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))

    result = subprocess.run(
        [sys.executable, "-m", "iam_lint.cli", "scan", str(policy_file), "--format", "json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    findings = json.loads(result.stdout)
    rules = {f["rule"] for f in findings}
    assert "FULL_ADMIN_ACCESS" in rules


def test_cli_clean_policy_exits_zero(tmp_path):
    policy_file = tmp_path / "clean.json"
    policy_file.write_text(json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]}))

    result = subprocess.run(
        [sys.executable, "-m", "iam_lint.cli", "scan", str(policy_file), "--format", "json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
