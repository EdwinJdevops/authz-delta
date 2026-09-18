"""Pure reachability join for the supported authorization path."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from .facts import (
    EKSAccessEntry,
    IAMRoleTrust,
    IAMSubjectConstraint,
    RBACBinding,
    RBACRole,
    WorkflowRoleRequest,
)
from .model import Capability, Diagnostic, ResultState, Snapshot, SourceLocation

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _string_like(value: str, pattern: str) -> bool:
    """Match only the '*' and '?' wildcards supported by IAM StringLike."""
    expression = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(expression, value) is not None


def _matches(subject: str, constraint: IAMSubjectConstraint) -> bool:
    if constraint.operator == "StringEquals":
        return subject == constraint.value
    if constraint.operator == "StringLike":
        return _string_like(subject, constraint.value)
    return False


def _subject(repository: str, request: WorkflowRoleRequest) -> str | None:
    if request.environment is None:
        return None
    environment = request.environment.replace(":", "%3A")
    return f"repo:{repository}:environment:{environment}"


def _role_key(binding: RBACBinding) -> tuple[str, str, str | None]:
    namespace = binding.namespace if binding.role_kind == "Role" else None
    return binding.role_kind, binding.role_name, namespace


def _scope(binding: RBACBinding) -> str:
    if binding.kind == "ClusterRoleBinding":
        return "cluster"
    if binding.namespace is None:
        raise AssertionError("validated RoleBinding has no namespace")
    return f"namespace:{binding.namespace}"


def _merge_evidence(items: Iterable[SourceLocation]) -> tuple[SourceLocation, ...]:
    return tuple(sorted(set(items)))


def build_snapshot(
    *,
    repository: str,
    workflows: tuple[WorkflowRoleRequest, ...],
    role_trusts: tuple[IAMRoleTrust, ...],
    access_entries: tuple[EKSAccessEntry, ...],
    roles: tuple[RBACRole, ...],
    bindings: tuple[RBACBinding, ...],
    diagnostics: tuple[Diagnostic, ...] = (),
) -> Snapshot:
    """Join only complete, supported, statically evidenced paths."""
    if _REPOSITORY.fullmatch(repository) is None:
        raise ValueError("repository must use the literal owner/name form")

    output_diagnostics: list[Diagnostic] = list(diagnostics)
    workflow_roles = {item.role_arn for item in workflows}
    relevant_entries = tuple(item for item in access_entries if item.role_arn in workflow_roles)
    clusters = {item.cluster for item in relevant_entries}
    if len(clusters) > 1:
        output_diagnostics.append(
            Diagnostic(
                code="rbac_cluster_scope_ambiguous",
                state=ResultState.INDETERMINATE,
                message=(
                    "RBAC manifests have no cluster identity, but relevant EKS access entries "
                    "span multiple clusters."
                ),
                anchors=tuple(sorted(workflow_roles.union(clusters))),
                evidence=_merge_evidence(
                    source for entry in relevant_entries for source in entry.evidence
                ),
            )
        )
        return Snapshot(
            capabilities=frozenset(),
            diagnostics=tuple(sorted(set(output_diagnostics))),
        )

    trusts_by_role: dict[str, list[IAMRoleTrust]] = defaultdict(list)
    for trust in role_trusts:
        trusts_by_role[trust.role_arn].append(trust)
    entries_by_role: dict[str, list[EKSAccessEntry]] = defaultdict(list)
    for entry in relevant_entries:
        entries_by_role[entry.role_arn].append(entry)
    bindings_by_group: dict[str, list[RBACBinding]] = defaultdict(list)
    for rbac_binding in bindings:
        for group in rbac_binding.groups:
            bindings_by_group[group].append(rbac_binding)

    roles_by_key: dict[tuple[str, str, str | None], RBACRole] = {}
    ambiguous_role_keys: set[tuple[str, str, str | None]] = set()
    for role_fact in roles:
        key = (role_fact.kind, role_fact.name, role_fact.namespace)
        if key in roles_by_key and roles_by_key[key] != role_fact:
            ambiguous_role_keys.add(key)
        else:
            roles_by_key[key] = role_fact
    for key in sorted(ambiguous_role_keys):
        role_kind, role_name, namespace = key
        output_diagnostics.append(
            Diagnostic(
                code="rbac_role_ambiguous",
                state=ResultState.INDETERMINATE,
                message="Multiple different RBAC role definitions have the same identity.",
                anchors=tuple(part for part in (role_kind, role_name, namespace) if part),
            )
        )
        roles_by_key.pop(key, None)

    capability_evidence: dict[tuple[str, ...], set[SourceLocation]] = defaultdict(set)
    for request in workflows:
        subject = _subject(repository, request)
        if subject is None:
            output_diagnostics.append(
                Diagnostic(
                    code="github_subject_not_static",
                    state=ResultState.INDETERMINATE,
                    message=(
                        "Release 0 proves GitHub OIDC subjects only for jobs with a literal "
                        "environment."
                    ),
                    anchors=(request.workflow, request.job, request.role_arn),
                    evidence=request.evidence,
                )
            )
            continue
        for trust in trusts_by_role.get(request.role_arn, []):
            if not any(_matches(subject, item) for item in trust.subject_constraints):
                continue
            for entry in entries_by_role.get(request.role_arn, []):
                for group in entry.groups:
                    for rbac_binding in bindings_by_group.get(group, []):
                        key = _role_key(rbac_binding)
                        rbac_role = roles_by_key.get(key)
                        if rbac_role is None:
                            continue
                        scope = _scope(rbac_binding)
                        for rule in rbac_role.rules:
                            for api_group in rule.api_groups:
                                for resource in rule.resources:
                                    for verb in rule.verbs:
                                        identity = (
                                            request.workflow,
                                            request.job,
                                            subject,
                                            request.role_arn,
                                            entry.cluster,
                                            group,
                                            scope,
                                            api_group,
                                            resource,
                                            verb,
                                        )
                                        capability_evidence[identity].update(request.evidence)
                                        capability_evidence[identity].update(trust.evidence)
                                        capability_evidence[identity].update(entry.evidence)
                                        capability_evidence[identity].update(rbac_binding.evidence)
                                        capability_evidence[identity].update(rbac_role.evidence)

    capabilities = frozenset(
        Capability(
            workflow=identity[0],
            job=identity[1],
            oidc_subject=identity[2],
            role_arn=identity[3],
            cluster=identity[4],
            kubernetes_group=identity[5],
            scope=identity[6],
            api_group=identity[7],
            resource=identity[8],
            verb=identity[9],
            evidence=tuple(sorted(evidence)),
        )
        for identity, evidence in capability_evidence.items()
    )
    return Snapshot(
        capabilities=capabilities,
        diagnostics=tuple(sorted(set(output_diagnostics))),
    )
