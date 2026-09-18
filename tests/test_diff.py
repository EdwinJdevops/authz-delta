from authz_delta.diff import compare_snapshots
from authz_delta.model import (
    Capability,
    Diagnostic,
    ResultState,
    Snapshot,
    SourceLocation,
)


def capability(oidc_subject: str = "repo:acme/platform:environment:staging") -> Capability:
    return Capability(
        workflow="deploy.yml",
        job="deploy",
        oidc_subject=oidc_subject,
        role_arn="arn:aws:iam::123456789012:role/deployer",
        cluster="arn:aws:eks:us-east-1:123456789012:cluster/platform",
        kubernetes_group="platform-deployers",
        scope="namespace:staging",
        api_group="apps",
        resource="deployments",
        verb="patch",
        evidence=(SourceLocation(file="workflow.yml"),),
    )


def test_compare_returns_only_added_proven_path() -> None:
    original = capability()
    expanded = capability("repo:acme/platform:*")

    delta = compare_snapshots(
        Snapshot(capabilities=frozenset({original})),
        Snapshot(capabilities=frozenset({original, expanded})),
    )

    assert delta.newly_reachable == (expanded,)
    assert delta.removed == ()
    assert delta.diagnostics == ()


def test_relevant_unknown_suppresses_newly_reachable_finding() -> None:
    expanded = capability("repo:acme/platform:*")
    diagnostic = Diagnostic(
        code="terraform_unknown_value",
        state=ResultState.INDETERMINATE,
        message="The IAM role ARN is unknown in the before revision.",
        anchors=(expanded.role_arn,),
    )

    delta = compare_snapshots(
        Snapshot(capabilities=frozenset(), diagnostics=(diagnostic,)),
        Snapshot(capabilities=frozenset({expanded})),
    )

    assert delta.newly_reachable == ()
    assert any(item.code == "indeterminate_delta" for item in delta.diagnostics)


def test_unrelated_unknown_does_not_suppress_finding() -> None:
    expanded = capability("repo:acme/platform:*")
    diagnostic = Diagnostic(
        code="terraform_unknown_value",
        state=ResultState.INDETERMINATE,
        message="An unrelated role is unknown.",
        anchors=("arn:aws:iam::123456789012:role/unrelated",),
    )

    delta = compare_snapshots(
        Snapshot(capabilities=frozenset(), diagnostics=(diagnostic,)),
        Snapshot(capabilities=frozenset({expanded})),
    )

    assert delta.newly_reachable == (expanded,)
