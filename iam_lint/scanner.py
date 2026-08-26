"""
Core scanning logic for iam-lint.

lint_policy() takes a parsed IAM policy document (identity-based policy
JSON, already loaded into a dict) and returns a list of findings, each
shaped as:

    {"statement_index": int, "rule": str, "severity": str, "message": str}

severity is one of "critical", "high", "medium" — see RULE_SEVERITY below.
"""


ESCALATION_ACTIONS = {
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "sts:AssumeRole",
}

MFA_SENSITIVE_ACTIONS = ESCALATION_ACTIONS | {"iam:PassRole"}

RULE_SEVERITY = {
    "FULL_ADMIN_ACCESS": "critical",
    "PRIVILEGE_ESCALATION_RISK": "critical",
    "WILDCARD_PRINCIPAL": "critical",
    "WILDCARD_ACTION": "high",
    "WILDCARD_RESOURCE": "high",
    "PASSROLE_UNRESTRICTED": "high",
    "MISSING_MFA_CONDITION": "medium",
}


def make_finding(index, rule, message):
    return {
        "statement_index": index,
        "rule": rule,
        "severity": RULE_SEVERITY[rule],
        "message": message,
    }


def normalize_actions(statement):
    action = statement.get("Action", [])
    if isinstance(action, list):
        return action
    return [action]


def has_wildcard(items):
    return "*" in items


def safe_get_statements(policy):
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement", [])
    if isinstance(statements, list):
        return statements
    return [statements]


def normalize_principal_values(statement):
    """
    Principal (only present on trust/resource-based policy statements) can be:
      - the string "*"                          -> ["*"]
      - a dict like {"AWS": "*"}                 -> ["*"]
      - a dict like {"AWS": ["arn:...", "*"]}     -> ["arn:...", "*"]
      - a dict with multiple keys, e.g. {"AWS": "...", "Service": "..."}
      - missing entirely (most identity policies) -> []

    Always return a flat list of principal value strings, so has_wildcard()
    can be reused on it the same way it's used for actions and resources.
    """
    principal = statement.get("Principal")
    if principal is None:
        return []
    if isinstance(principal, str):
        return [principal]
    if isinstance(principal, dict):
        values = []
        for value in principal.values():
            if isinstance(value, list):
                values.extend(value)
            else:
                values.append(value)
        return values
    return []


def has_mfa_condition(statement):
    """
    A Condition block looks like:
        "Condition": {
            "Bool": {"aws:MultiFactorAuthPresent": "true"}
        }
    The outer key ("Bool", "BoolIfExists", ...) can vary, but what matters
    is whether "aws:MultiFactorAuthPresent" appears as a key anywhere inside
    one of the inner condition-operator dicts.

    Return True if an MFA condition is present, False otherwise (including
    when Condition is missing or malformed).
    """
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False
    for operator_block in condition.values():
        if isinstance(operator_block, dict) and "aws:MultiFactorAuthPresent" in operator_block:
            return True
    return False


def lint_policy(policy):
    findings = []
    for index, statement in enumerate(safe_get_statements(policy)):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue

        actions = normalize_actions(statement)
        resources = statement.get("Resource", [])
        if not isinstance(resources, list):
            resources = [resources]

        action_wildcard = has_wildcard(actions)
        resource_wildcard = has_wildcard(resources)

        if action_wildcard:
            findings.append(make_finding(
                index, "WILDCARD_ACTION",
                "Action includes \"*\", granting every action.",
            ))

        if resource_wildcard:
            findings.append(make_finding(
                index, "WILDCARD_RESOURCE",
                "Resource includes \"*\", applying account-wide.",
            ))

        if "iam:PassRole" in actions and resource_wildcard:
            findings.append(make_finding(
                index, "PASSROLE_UNRESTRICTED",
                "iam:PassRole is not restricted to a specific role ARN.",
            ))

        if action_wildcard and resource_wildcard:
            findings.append(make_finding(
                index, "FULL_ADMIN_ACCESS",
                "Action and Resource are both \"*\", granting unrestricted admin access.",
            ))

        if any(action in ESCALATION_ACTIONS for action in actions) and resource_wildcard:
            findings.append(make_finding(
                index, "PRIVILEGE_ESCALATION_RISK",
                "Action allows privilege escalation (create keys, attach policies, or assume roles) without a resource restriction.",
            ))

        if has_wildcard(normalize_principal_values(statement)):
            findings.append(make_finding(
                index, "WILDCARD_PRINCIPAL",
                "Principal is not restricted — this grants access to anyone.",
            ))

        if any(action in MFA_SENSITIVE_ACTIONS for action in actions) and not has_mfa_condition(statement):
            findings.append(make_finding(
                index, "MISSING_MFA_CONDITION",
                "Sensitive action is allowed without requiring MFA (aws:MultiFactorAuthPresent).",
            ))

    return findings
