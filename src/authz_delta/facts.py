"""Extractor facts that are not yet authorization conclusions."""

from __future__ import annotations

from dataclasses import dataclass

from .model import SourceLocation


@dataclass(frozen=True, order=True)
class WorkflowRoleRequest:
    """A literal GitHub Actions request to assume one IAM role using OIDC."""

    workflow: str
    job: str
    role_arn: str
    events: tuple[str, ...]
    environment: str | None
    evidence: tuple[SourceLocation, ...]


@dataclass(frozen=True, order=True)
class IAMSubjectConstraint:
    """One supported IAM operator and GitHub OIDC subject value."""

    operator: str
    value: str


@dataclass(frozen=True, order=True)
class IAMRoleTrust:
    """Supported GitHub OIDC subjects allowed to assume one IAM role."""

    role_arn: str
    subject_constraints: tuple[IAMSubjectConstraint, ...]
    evidence: tuple[SourceLocation, ...]


@dataclass(frozen=True, order=True)
class EKSAccessEntry:
    """Concrete EKS access-entry mapping from an IAM role to groups."""

    role_arn: str
    cluster: str
    groups: tuple[str, ...]
    evidence: tuple[SourceLocation, ...]


@dataclass(frozen=True, order=True)
class RBACRule:
    """One concrete Kubernetes resource rule."""

    api_groups: tuple[str, ...]
    resources: tuple[str, ...]
    verbs: tuple[str, ...]


@dataclass(frozen=True, order=True)
class RBACRole:
    """A Role or ClusterRole with statically represented rules."""

    kind: str
    name: str
    namespace: str | None
    rules: tuple[RBACRule, ...]
    evidence: tuple[SourceLocation, ...]


@dataclass(frozen=True, order=True)
class RBACBinding:
    """A group subject binding to a Role or ClusterRole."""

    kind: str
    name: str
    namespace: str | None
    role_kind: str
    role_name: str
    groups: tuple[str, ...]
    evidence: tuple[SourceLocation, ...]
