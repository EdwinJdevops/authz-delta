"""Counterexamples that must not produce affirmative authorization conclusions."""

import json
from pathlib import Path

import pytest
from test_analyze_cli import write_revision
from test_diff import capability

from authz_delta.builder import build_revision
from authz_delta.diff import compare_snapshots
from authz_delta.extractors.github import extract_workflow
from authz_delta.extractors.kubernetes import extract_rbac
from authz_delta.extractors.terraform import extract_terraform_plan
from authz_delta.model import Diagnostic, ResultState, Snapshot


def plan_with_policy(tmp_path: Path, statements: object) -> Path:
    plan, _ = write_revision(tmp_path / "revision", verbs=["get"])
    data = json.loads(plan.read_text())
    data["planned_values"]["root_module"]["resources"][0]["values"]["assume_role_policy"] = (
        json.dumps({"Version": "2012-10-17", "Statement": statements})
    )
    plan.write_text(json.dumps(data))
    return plan


def allow_statement() -> dict[str, object]:
    return {
        "Effect": "Allow",
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Principal": {
            "Federated": (
                "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
            )
        },
        "Condition": {
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/payments:*"},
        },
    }


def test_deny_statement_invalidates_extracted_allow(tmp_path: Path) -> None:
    deny = {**allow_statement(), "Effect": "Deny"}
    result = extract_terraform_plan(plan_with_policy(tmp_path, [allow_statement(), deny]))
    assert not result.role_trusts
    assert any(d.code == "iam_deny_not_evaluated" for d in result.diagnostics)


@pytest.mark.parametrize("statements", [None, "bad", [None], [{"Effect": "Maybe"}]])
def test_malformed_statements_are_diagnostic(tmp_path: Path, statements: object) -> None:
    result = extract_terraform_plan(plan_with_policy(tmp_path, statements))
    assert not result.role_trusts
    assert result.diagnostics


@pytest.mark.parametrize(
    "conditions",
    [
        {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.*"}},
        {
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:aud": "other.*"},
        },
        {"StringLike": {"token.actions.githubusercontent.com:aud": "[s]ts.amazonaws.com"}},
    ],
)
def test_audience_operators_keep_their_semantics(tmp_path: Path, conditions: object) -> None:
    statement = {**allow_statement(), "Condition": conditions}
    result = extract_terraform_plan(plan_with_policy(tmp_path, statement))
    assert not result.role_trusts


def test_nested_unknown_group_is_not_concrete(tmp_path: Path) -> None:
    plan, _ = write_revision(tmp_path / "revision", verbs=["get"])
    data = json.loads(plan.read_text())
    data["resource_changes"] = [
        {
            "address": "aws_eks_access_entry.deployer",
            "change": {"after_unknown": {"kubernetes_groups": [True]}},
        }
    ]
    plan.write_text(json.dumps(data))
    result = extract_terraform_plan(plan)
    assert not result.access_entries
    assert any(d.code == "terraform_value_unknown" for d in result.diagnostics)


@pytest.mark.parametrize("broken", ["plan", "rbac", "workflows"])
def test_incomplete_before_cannot_prove_new_access(tmp_path: Path, broken: str) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before_plan, before_rbac = write_revision(before, verbs=["get"])
    after_plan, after_rbac = write_revision(after, verbs=["get", "patch"])
    if broken == "plan":
        before_plan.write_text("{invalid")
    elif broken == "rbac":
        before_rbac.write_text("kind: [")
    else:
        (before / ".github/workflows/deploy.yml").unlink()
    builds = [
        build_revision(
            repository="acme/payments",
            oidc_subject_prefix="repo:acme/payments",
            root=root,
            plan=plan,
            rbac_inputs=(rbac,),
        )
        for root, plan, rbac in [
            (before, before_plan, before_rbac),
            (after, after_plan, after_rbac),
        ]
    ]
    delta = compare_snapshots(builds[0].snapshot, builds[1].snapshot)
    assert delta.diagnostics
    assert not delta.newly_reachable


def test_unknown_after_cannot_prove_access_removed() -> None:
    existing = capability()
    diagnostic = Diagnostic("unreadable", ResultState.INDETERMINATE, "Cannot read input")
    delta = compare_snapshots(Snapshot(frozenset({existing})), Snapshot(frozenset(), (diagnostic,)))
    assert not delta.removed
    assert any(d.code == "indeterminate_removal" for d in delta.diagnostics)


@pytest.mark.parametrize(
    "option",
    [
        "audience: custom-audience",
        "force-skip-oidc: true",
        "role-chaining: true",
        "aws-access-key-id: fake-test-value",
    ],
)
def test_unmodeled_credential_options_do_not_prove_oidc(tmp_path: Path, option: str) -> None:
    root = tmp_path / "revision"
    write_revision(root, verbs=["get"])
    workflow = root / ".github/workflows/deploy.yml"
    workflow.write_text(workflow.read_text() + "          " + option + "\n")
    result = extract_workflow(workflow)
    assert not result.role_requests
    assert result.diagnostics


def test_wildcard_grant_is_not_an_exact_capability(tmp_path: Path) -> None:
    _, rbac = write_revision(tmp_path / "revision", verbs=["'*'"])
    result = extract_rbac(rbac)
    assert not result.roles
    assert any(d.code == "rbac_wildcard_unsupported" for d in result.diagnostics)
