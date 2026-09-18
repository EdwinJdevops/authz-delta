from authz_delta.facts import (
    EKSAccessEntry,
    IAMRoleTrust,
    IAMSubjectConstraint,
    RBACBinding,
    RBACRole,
    RBACRule,
    WorkflowRoleRequest,
)
from authz_delta.graph import build_snapshot
from authz_delta.model import SourceLocation

ROLE_ARN = "arn:aws:iam::123456789012:role/deployer"
SOURCE = (SourceLocation(file="fixture"),)


def workflow(environment: str | None = "production") -> WorkflowRoleRequest:
    return WorkflowRoleRequest(
        workflow=".github/workflows/deploy.yml",
        job="deploy",
        role_arn=ROLE_ARN,
        events=("push",),
        environment=environment,
        evidence=SOURCE,
    )


def trust(operator: str, value: str) -> IAMRoleTrust:
    return IAMRoleTrust(
        role_arn=ROLE_ARN,
        subject_constraints=(IAMSubjectConstraint(operator=operator, value=value),),
        evidence=SOURCE,
    )


def access(cluster: str = "production") -> EKSAccessEntry:
    return EKSAccessEntry(
        role_arn=ROLE_ARN,
        cluster=cluster,
        groups=("eks-deployers",),
        evidence=SOURCE,
    )


def role(kind: str = "Role") -> RBACRole:
    return RBACRole(
        kind=kind,
        name="deployer",
        namespace="payments" if kind == "Role" else None,
        rules=(RBACRule(api_groups=("apps",), resources=("deployments",), verbs=("get", "patch")),),
        evidence=SOURCE,
    )


def binding(role_kind: str = "Role") -> RBACBinding:
    return RBACBinding(
        kind="RoleBinding",
        name="deployers",
        namespace="payments",
        role_kind=role_kind,
        role_name="deployer",
        groups=("eks-deployers",),
        evidence=SOURCE,
    )


def test_builds_complete_environment_bound_capabilities() -> None:
    snapshot = build_snapshot(
        repository="acme/payments",
        workflows=(workflow(),),
        role_trusts=(trust("StringLike", "repo:acme/payments:environment:*"),),
        access_entries=(access(),),
        roles=(role(),),
        bindings=(binding(),),
    )

    assert snapshot.diagnostics == ()
    assert len(snapshot.capabilities) == 2
    assert {item.verb for item in snapshot.capabilities} == {"get", "patch"}
    capability = sorted(snapshot.capabilities)[0]
    assert capability.oidc_subject == "repo:acme/payments:environment:production"
    assert capability.scope == "namespace:payments"
    assert capability.cluster == "production"


def test_string_equals_does_not_treat_asterisk_as_wildcard() -> None:
    snapshot = build_snapshot(
        repository="acme/payments",
        workflows=(workflow(),),
        role_trusts=(trust("StringEquals", "repo:acme/payments:environment:*"),),
        access_entries=(access(),),
        roles=(role(),),
        bindings=(binding(),),
    )

    assert snapshot.capabilities == frozenset()


def test_role_not_mapped_to_eks_has_no_capability() -> None:
    snapshot = build_snapshot(
        repository="acme/payments",
        workflows=(workflow(),),
        role_trusts=(trust("StringLike", "repo:acme/payments:*"),),
        access_entries=(),
        roles=(role(),),
        bindings=(binding(),),
    )

    assert snapshot.capabilities == frozenset()


def test_role_binding_to_cluster_role_is_namespace_scoped() -> None:
    snapshot = build_snapshot(
        repository="acme/payments",
        workflows=(workflow(),),
        role_trusts=(trust("StringLike", "repo:acme/payments:*"),),
        access_entries=(access(),),
        roles=(role("ClusterRole"),),
        bindings=(binding("ClusterRole"),),
    )

    assert {item.scope for item in snapshot.capabilities} == {"namespace:payments"}


def test_multiple_clusters_do_not_reuse_unscoped_rbac_manifests() -> None:
    snapshot = build_snapshot(
        repository="acme/payments",
        workflows=(workflow(),),
        role_trusts=(trust("StringLike", "repo:acme/payments:*"),),
        access_entries=(access("production"), access("staging")),
        roles=(role(),),
        bindings=(binding(),),
    )

    assert snapshot.capabilities == frozenset()
    assert {item.code for item in snapshot.diagnostics} == {"rbac_cluster_scope_ambiguous"}


def test_workflow_without_static_environment_is_indeterminate() -> None:
    snapshot = build_snapshot(
        repository="acme/payments",
        workflows=(workflow(None),),
        role_trusts=(trust("StringLike", "repo:acme/payments:*"),),
        access_entries=(access(),),
        roles=(role(),),
        bindings=(binding(),),
    )

    assert snapshot.capabilities == frozenset()
    assert {item.code for item in snapshot.diagnostics} == {"github_subject_not_static"}
