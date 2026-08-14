from iam_lint.scanner import lint_policy


def test_wildcard_action_flagged():
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}]}
    findings = lint_policy(policy)
    assert len(findings) == 1
    assert findings[0]["rule"] == "WILDCARD_ACTION"
    assert findings[0]["statement_index"] == 0


def test_wildcard_resource_flagged():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    findings = lint_policy(policy)
    assert len(findings) == 1
    assert findings[0]["rule"] == "WILDCARD_RESOURCE"


def test_passrole_unrestricted_flagged_alongside_wildcard_resource():
    policy = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "PASSROLE_UNRESTRICTED" in rules
    assert "WILDCARD_RESOURCE" in rules


def test_clean_statement_no_findings():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]}
    assert lint_policy(policy) == []


def test_deny_statement_ignored():
    policy = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    assert lint_policy(policy) == []


def test_passrole_scoped_to_role_not_flagged():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::111122223333:role/app-role",
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "PASSROLE_UNRESTRICTED" not in rules


def test_multiple_statements_indexed_correctly():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"},
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
        ]
    }
    findings = lint_policy(policy)
    indices = {f["statement_index"] for f in findings}
    assert indices == {1}


def test_single_statement_not_wrapped_in_list():
    policy = {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
    findings = lint_policy(policy)
    assert len(findings) >= 1
    assert findings[0]["statement_index"] == 0


def test_malformed_policy_returns_empty():
    assert lint_policy(None) == []
    assert lint_policy("not a policy") == []
    assert lint_policy({}) == []


# --- New for this session: combined full-admin detection ---

def test_full_admin_flagged_when_action_and_resource_wildcard():
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "FULL_ADMIN_ACCESS" in rules


def test_full_admin_not_flagged_when_only_action_wildcard():
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "FULL_ADMIN_ACCESS" not in rules


def test_full_admin_not_flagged_when_only_resource_wildcard():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "FULL_ADMIN_ACCESS" not in rules


# --- New for this session: privilege-escalation actions beyond PassRole ---

def test_privilege_escalation_flagged_for_create_access_key_with_wildcard_resource():
    policy = {"Statement": [{"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "PRIVILEGE_ESCALATION_RISK" in rules


def test_privilege_escalation_flagged_for_assume_role_with_wildcard_resource():
    policy = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "PRIVILEGE_ESCALATION_RISK" in rules


def test_privilege_escalation_not_flagged_when_scoped_to_specific_resource():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:AttachUserPolicy",
                "Resource": "arn:aws:iam::111122223333:user/alice",
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "PRIVILEGE_ESCALATION_RISK" not in rules


def test_privilege_escalation_not_flagged_for_unrelated_action():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "PRIVILEGE_ESCALATION_RISK" not in rules


# --- New for this session: wildcard Principal in trust/resource-based policies ---

def test_wildcard_principal_string_flagged():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::111122223333:role/app-role"}
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "WILDCARD_PRINCIPAL" in rules


def test_wildcard_principal_dict_aws_star_flagged():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::111122223333:role/app-role",
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "WILDCARD_PRINCIPAL" in rules


def test_wildcard_principal_inside_list_flagged():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "*"]},
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::111122223333:role/app-role",
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "WILDCARD_PRINCIPAL" in rules


def test_scoped_principal_specific_account_not_flagged():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::111122223333:role/app-role",
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "WILDCARD_PRINCIPAL" not in rules


def test_missing_principal_not_flagged():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "WILDCARD_PRINCIPAL" not in rules


# --- New for this session: missing MFA condition on sensitive actions ---

def test_missing_mfa_flagged_for_passrole_without_condition():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::111122223333:role/app-role"}
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "MISSING_MFA_CONDITION" in rules


def test_missing_mfa_flagged_for_escalation_action_without_condition():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:AttachUserPolicy",
                "Resource": "arn:aws:iam::111122223333:user/alice",
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "MISSING_MFA_CONDITION" in rules


def test_missing_mfa_not_flagged_when_condition_present():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::111122223333:role/app-role",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "MISSING_MFA_CONDITION" not in rules


def test_missing_mfa_not_flagged_with_boolifexists_condition():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::111122223333:role/app-role",
                "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}},
            }
        ]
    }
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "MISSING_MFA_CONDITION" not in rules


def test_missing_mfa_not_flagged_for_unrelated_action():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]}
    findings = lint_policy(policy)
    rules = {f["rule"] for f in findings}
    assert "MISSING_MFA_CONDITION" not in rules
