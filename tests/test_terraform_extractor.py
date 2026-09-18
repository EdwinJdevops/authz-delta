import json
from pathlib import Path

from authz_delta.extractors.terraform import extract_terraform_plan
from authz_delta.model import ResultState


def write_plan(tmp_path: Path, plan: object) -> Path:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def base_plan(resources: list[dict[str, object]]) -> dict[str, object]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": resources}},
        "resource_changes": [],
    }


def test_extracts_concrete_github_trust_and_eks_access(tmp_path: Path) -> None:
    trust = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {
                "Federated": (
                    "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                )
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/payments:*"},
            },
        },
    }
    plan = base_plan(
        [
            {
                "address": "module.identity.aws_iam_role.deployer",
                "mode": "managed",
                "type": "aws_iam_role",
                "name": "deployer",
                "values": {
                    "arn": "arn:aws:iam::123456789012:role/deployer",
                    "assume_role_policy": json.dumps(trust),
                },
            },
            {
                "address": "aws_eks_access_entry.deployer",
                "mode": "managed",
                "type": "aws_eks_access_entry",
                "name": "deployer",
                "values": {
                    "cluster_name": "production",
                    "principal_arn": "arn:aws:iam::123456789012:role/deployer",
                    "kubernetes_groups": ["deployers", "viewers"],
                },
            },
        ]
    )
    path = write_plan(tmp_path, plan)

    result = extract_terraform_plan(path, display_path="plans/after.json")

    assert result.diagnostics == ()
    assert len(result.role_trusts) == 1
    assert result.role_trusts[0].role_arn.endswith(":role/deployer")
    assert len(result.role_trusts[0].subject_constraints) == 1
    constraint = result.role_trusts[0].subject_constraints[0]
    assert (constraint.operator, constraint.value) == (
        "StringLike",
        "repo:acme/payments:*",
    )
    assert len(result.access_entries) == 1
    assert result.access_entries[0].cluster == "production"
    assert result.access_entries[0].groups == ("deployers", "viewers")


def test_unsupported_trust_condition_operator_is_indeterminate(tmp_path: Path) -> None:
    trust = {
        "Statement": {
            "Effect": "Allow",
            "Principal": {
                "Federated": (
                    "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                )
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "ForAnyValue:StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}
            },
        }
    }
    plan = base_plan(
        [
            {
                "address": "aws_iam_role.deployer",
                "mode": "managed",
                "type": "aws_iam_role",
                "name": "deployer",
                "values": {
                    "arn": "arn:aws:iam::123456789012:role/deployer",
                    "assume_role_policy": json.dumps(trust),
                },
            }
        ]
    )

    result = extract_terraform_plan(write_plan(tmp_path, plan))

    assert result.role_trusts == ()
    assert {item.code for item in result.diagnostics} == {"iam_condition_operator_unsupported"}
    assert result.diagnostics[0].state is ResultState.INDETERMINATE


def test_after_unknown_required_value_is_not_treated_as_concrete(tmp_path: Path) -> None:
    plan = base_plan(
        [
            {
                "address": "aws_eks_access_entry.deployer",
                "mode": "managed",
                "type": "aws_eks_access_entry",
                "name": "deployer",
                "values": {
                    "cluster_name": "production",
                    "principal_arn": None,
                    "kubernetes_groups": ["deployers"],
                },
            }
        ]
    )
    plan["resource_changes"] = [
        {
            "address": "aws_eks_access_entry.deployer",
            "change": {"after_unknown": {"principal_arn": True}},
        }
    ]

    result = extract_terraform_plan(write_plan(tmp_path, plan))

    assert result.access_entries == ()
    assert {item.code for item in result.diagnostics} == {"terraform_value_unknown"}


def test_malformed_trust_policy_is_diagnostic(tmp_path: Path) -> None:
    plan = base_plan(
        [
            {
                "address": "aws_iam_role.deployer",
                "mode": "managed",
                "type": "aws_iam_role",
                "name": "deployer",
                "values": {
                    "arn": "arn:aws:iam::123456789012:role/deployer",
                    "assume_role_policy": "{not-json}",
                },
            }
        ]
    )

    result = extract_terraform_plan(write_plan(tmp_path, plan))

    assert result.role_trusts == ()
    assert {item.code for item in result.diagnostics} == {"iam_trust_policy_invalid"}


def test_eks_access_policy_association_is_explicitly_unsupported(tmp_path: Path) -> None:
    plan = base_plan(
        [
            {
                "address": "aws_eks_access_policy_association.admin",
                "mode": "managed",
                "type": "aws_eks_access_policy_association",
                "name": "admin",
                "values": {
                    "cluster_name": "production",
                    "principal_arn": "arn:aws:iam::123456789012:role/deployer",
                    "policy_arn": (
                        "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
                    ),
                },
            }
        ]
    )

    result = extract_terraform_plan(write_plan(tmp_path, plan))

    assert result.access_entries == ()
    assert {item.code for item in result.diagnostics} == {
        "eks_access_policy_association_unsupported"
    }
    assert result.diagnostics[0].state is ResultState.INDETERMINATE
