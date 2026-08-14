# iam-lint

Static analysis for AWS IAM policy documents. Catches least-privilege
violations — wildcard grants, unrestricted `iam:PassRole`, and other
common over-permissioning patterns — before they reach production.

## Status

Early development. Core scanning engine in progress; CLI and packaging
for distribution coming next.

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

## License

MIT
