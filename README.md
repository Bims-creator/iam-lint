# iam-lint

Static analysis for AWS IAM policy documents. Catches least-privilege
violations — wildcard grants, unrestricted `iam:PassRole`, and other
common over-permissioning patterns — before they reach production.

## Status

Early development. Core scanning engine and CLI both working; PyPI
distribution not published yet — install from source for now.

## Install (development)

```bash
git clone https://github.com/Bims-creator/iam-lint.git
cd iam-lint
python -m venv venv
venv\Scripts\activate
pip install -e ".[dev]"
```

## Run tests

```bash
pytest -v
```

## Usage

### CLI

```bash
iam-lint scan policy.json
```

```
[WILDCARD_ACTION] statement 0: Action includes "*", granting every action.
[WILDCARD_RESOURCE] statement 0: Resource includes "*", applying account-wide.
[FULL_ADMIN_ACCESS] statement 0: Action and Resource are both "*", granting unrestricted admin access.
```

Exits with code `1` if any findings are reported, `0` otherwise — drop it
into CI as a policy gate. Add `--format json` for machine-readable output.

### As a library

```python
from iam_lint import lint_policy

policy = {
    "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}
    ]
}

for finding in lint_policy(policy):
    print(finding)
```

## Rules

| Rule | Detects |
|---|---|
| `WILDCARD_ACTION` | `Action` includes `"*"`, granting every action |
| `WILDCARD_RESOURCE` | `Resource` includes `"*"`, applying account-wide |
| `PASSROLE_UNRESTRICTED` | `iam:PassRole` not restricted to a specific role ARN |
| `FULL_ADMIN_ACCESS` | Wildcard `Action` and `Resource` together in one statement |
| `PRIVILEGE_ESCALATION_RISK` | Actions like `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:PutUserPolicy`, or `sts:AssumeRole` granted without a resource restriction |
| `WILDCARD_PRINCIPAL` | Trust/resource-based policy `Principal` is `"*"` or includes it — grants access to anyone |
| `MISSING_MFA_CONDITION` | Sensitive actions allowed without requiring `aws:MultiFactorAuthPresent` |

## License

MIT
