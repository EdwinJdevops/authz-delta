"""Conservative Kubernetes RBAC manifest extraction."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.error import YAMLError

from ..facts import RBACBinding, RBACRole, RBACRule
from ..model import Diagnostic, ResultState, SourceLocation

_API_VERSION = "rbac.authorization.k8s.io/v1"
_KINDS = frozenset({"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"})


@dataclass(frozen=True)
class KubernetesExtraction:
    """Supported RBAC objects and explicit boundaries from one manifest file."""

    roles: tuple[RBACRole, ...]
    bindings: tuple[RBACBinding, ...]
    diagnostics: tuple[Diagnostic, ...]


def _line(value: object, key: object | None = None) -> int | None:
    location = getattr(value, "lc", None)
    if location is None:
        return None
    try:
        zero_based = location.key(key)[0] if key is not None else location.line
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    return int(zero_based) + 1


def _source(
    file: str,
    document: int,
    path: str,
    value: object,
    key: object | None = None,
) -> SourceLocation:
    return SourceLocation(
        file=file,
        document=document,
        path=path,
        line=_line(value, key),
    )


def _diagnostic(
    *,
    code: str,
    message: str,
    file: str,
    document: int,
    path: str,
    value: object,
    anchors: tuple[str, ...],
    key: object | None = None,
    state: ResultState = ResultState.INDETERMINATE,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        state=state,
        message=message,
        anchors=tuple(sorted(set(anchors))),
        evidence=(_source(file, document, path, value, key),),
    )


def _strings(value: object, *, allow_empty: bool = False) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) and (allow_empty or bool(item)) for item in value):
        return None
    return tuple(sorted(set(value)))


def _identity(
    document: Mapping[object, object],
) -> tuple[str, str, str | None] | None:
    kind = document.get("kind")
    metadata = document.get("metadata")
    if not isinstance(kind, str) or not isinstance(metadata, Mapping):
        return None
    name = metadata.get("name")
    namespace = metadata.get("namespace")
    if not isinstance(name, str) or not name:
        return None
    if namespace is not None and (not isinstance(namespace, str) or not namespace):
        return None
    return kind, name, namespace


def _extract_role(
    document: Mapping[object, object],
    *,
    file: str,
    document_index: int,
    kind: str,
    name: str,
    namespace: str | None,
) -> tuple[RBACRole | None, tuple[Diagnostic, ...]]:
    anchors = (kind, name) + ((namespace,) if namespace else ())
    if kind == "Role" and namespace is None:
        return None, (
            _diagnostic(
                code="rbac_namespace_absent",
                message="Role namespace is absent; apply-time namespace cannot be inferred.",
                file=file,
                document=document_index,
                path="metadata.namespace",
                value=document,
                anchors=anchors,
            ),
        )
    if kind == "ClusterRole" and "aggregationRule" in document:
        return None, (
            _diagnostic(
                code="rbac_aggregation_unsupported",
                message="Aggregated ClusterRoles require label-selection evaluation.",
                file=file,
                document=document_index,
                path="aggregationRule",
                value=document,
                key="aggregationRule",
                anchors=anchors,
            ),
        )
    raw_rules = document.get("rules", [])
    if not isinstance(raw_rules, list):
        return None, (
            _diagnostic(
                code="rbac_rules_invalid",
                message="RBAC rules must be an array.",
                file=file,
                document=document_index,
                path="rules",
                value=document,
                key="rules",
                anchors=anchors,
            ),
        )
    rules: list[RBACRule] = []
    diagnostics: list[Diagnostic] = []
    for index, raw_rule in enumerate(raw_rules):
        path = f"rules[{index}]"
        if not isinstance(raw_rule, Mapping):
            diagnostics.append(
                _diagnostic(
                    code="rbac_rule_invalid",
                    message="Each RBAC rule must be an object.",
                    file=file,
                    document=document_index,
                    path=path,
                    value=raw_rule,
                    anchors=anchors,
                )
            )
            continue
        if "resourceNames" in raw_rule:
            diagnostics.append(
                _diagnostic(
                    code="rbac_resource_names_unsupported",
                    message=(
                        "resourceNames restrictions cannot be flattened to resource-wide access."
                    ),
                    file=file,
                    document=document_index,
                    path=f"{path}.resourceNames",
                    value=raw_rule,
                    key="resourceNames",
                    anchors=anchors,
                )
            )
            continue
        if "nonResourceURLs" in raw_rule:
            diagnostics.append(
                _diagnostic(
                    code="rbac_non_resource_urls_not_evaluated",
                    message=(
                        "Non-resource URL authorization is outside the Release-0 capability model."
                    ),
                    file=file,
                    document=document_index,
                    path=f"{path}.nonResourceURLs",
                    value=raw_rule,
                    key="nonResourceURLs",
                    anchors=anchors,
                    state=ResultState.NOT_EVALUATED,
                )
            )
            continue
        api_groups = _strings(raw_rule.get("apiGroups"), allow_empty=True)
        resources = _strings(raw_rule.get("resources"))
        verbs = _strings(raw_rule.get("verbs"))
        if api_groups is None or resources is None or verbs is None:
            diagnostics.append(
                _diagnostic(
                    code="rbac_rule_invalid",
                    message="RBAC apiGroups, resources, and verbs must be concrete string arrays.",
                    file=file,
                    document=document_index,
                    path=path,
                    value=raw_rule,
                    anchors=anchors,
                )
            )
            continue
        rules.append(RBACRule(api_groups=api_groups, resources=resources, verbs=verbs))
    if diagnostics:
        return None, tuple(sorted(set(diagnostics)))
    return (
        RBACRole(
            kind=kind,
            name=name,
            namespace=namespace if kind == "Role" else None,
            rules=tuple(sorted(set(rules))),
            evidence=(
                _source(file, document_index, "metadata.name", document["metadata"], "name"),
            ),
        ),
        (),
    )


def _extract_binding(
    document: Mapping[object, object],
    *,
    file: str,
    document_index: int,
    kind: str,
    name: str,
    namespace: str | None,
) -> tuple[RBACBinding | None, tuple[Diagnostic, ...]]:
    anchors = (kind, name) + ((namespace,) if namespace else ())
    if kind == "RoleBinding" and namespace is None:
        return None, (
            _diagnostic(
                code="rbac_namespace_absent",
                message="RoleBinding namespace is absent; apply-time namespace cannot be inferred.",
                file=file,
                document=document_index,
                path="metadata.namespace",
                value=document,
                anchors=anchors,
            ),
        )
    role_ref = document.get("roleRef")
    if not isinstance(role_ref, Mapping):
        return None, (
            _diagnostic(
                code="rbac_role_ref_invalid",
                message="RBAC binding roleRef must be an object.",
                file=file,
                document=document_index,
                path="roleRef",
                value=document,
                key="roleRef",
                anchors=anchors,
            ),
        )
    role_kind = role_ref.get("kind")
    role_name = role_ref.get("name")
    role_api_group = role_ref.get("apiGroup")
    valid_role_kinds = {"ClusterRole"} if kind == "ClusterRoleBinding" else {"Role", "ClusterRole"}
    if (
        role_kind not in valid_role_kinds
        or not isinstance(role_name, str)
        or not role_name
        or role_api_group != "rbac.authorization.k8s.io"
    ):
        return None, (
            _diagnostic(
                code="rbac_role_ref_invalid",
                message="RBAC roleRef has an unsupported or invalid API group, kind, or name.",
                file=file,
                document=document_index,
                path="roleRef",
                value=role_ref,
                anchors=anchors,
            ),
        )
    subjects = document.get("subjects", [])
    if not isinstance(subjects, list):
        return None, (
            _diagnostic(
                code="rbac_subjects_invalid",
                message="RBAC subjects must be an array.",
                file=file,
                document=document_index,
                path="subjects",
                value=document,
                key="subjects",
                anchors=anchors,
            ),
        )
    groups: set[str] = set()
    for index, subject in enumerate(subjects):
        if not isinstance(subject, Mapping) or subject.get("kind") != "Group":
            continue
        group = subject.get("name")
        if (
            subject.get("apiGroup") != "rbac.authorization.k8s.io"
            or not isinstance(group, str)
            or not group
        ):
            return None, (
                _diagnostic(
                    code="rbac_group_subject_invalid",
                    message="RBAC Group subjects require the RBAC API group and a concrete name.",
                    file=file,
                    document=document_index,
                    path=f"subjects[{index}]",
                    value=subject,
                    anchors=anchors,
                ),
            )
        groups.add(group)
    if not groups:
        return None, ()
    return (
        RBACBinding(
            kind=kind,
            name=name,
            namespace=namespace if kind == "RoleBinding" else None,
            role_kind=str(role_kind),
            role_name=role_name,
            groups=tuple(sorted(groups)),
            evidence=(
                _source(file, document_index, "metadata.name", document["metadata"], "name"),
            ),
        ),
        (),
    )


def extract_rbac(path: Path, *, display_path: str | None = None) -> KubernetesExtraction:
    """Extract supported RBAC objects without rendering or contacting a cluster."""
    file = display_path or path.as_posix()
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return KubernetesExtraction(
            roles=(),
            bindings=(),
            diagnostics=(
                Diagnostic(
                    code="rbac_read_error",
                    state=ResultState.INDETERMINATE,
                    message=f"Cannot read Kubernetes manifest: {error}.",
                    anchors=(file,),
                    evidence=(SourceLocation(file=file),),
                ),
            ),
        )
    yaml: Any = YAML(typ="rt", pure=True)
    yaml.allow_duplicate_keys = False
    try:
        documents = list(yaml.load_all(source))
    except DuplicateKeyError as error:
        return KubernetesExtraction(
            roles=(),
            bindings=(),
            diagnostics=(
                Diagnostic(
                    code="yaml_duplicate_key",
                    state=ResultState.INDETERMINATE,
                    message=f"Manifest contains a duplicate YAML key: {error.problem}.",
                    anchors=(file,),
                    evidence=(SourceLocation(file=file),),
                ),
            ),
        )
    except YAMLError as error:
        problem = getattr(error, "problem", None)
        return KubernetesExtraction(
            roles=(),
            bindings=(),
            diagnostics=(
                Diagnostic(
                    code="yaml_parse_error",
                    state=ResultState.INDETERMINATE,
                    message=f"Manifest is not valid YAML: {problem or type(error).__name__}.",
                    anchors=(file,),
                    evidence=(SourceLocation(file=file),),
                ),
            ),
        )

    roles: list[RBACRole] = []
    bindings: list[RBACBinding] = []
    diagnostics: list[Diagnostic] = []
    for document_index, document in enumerate(documents):
        if document is None:
            continue
        if not isinstance(document, Mapping):
            diagnostics.append(
                _diagnostic(
                    code="kubernetes_document_invalid",
                    message="Kubernetes YAML document root must be an object.",
                    file=file,
                    document=document_index,
                    path="",
                    value=document,
                    anchors=(file,),
                )
            )
            continue
        kind = document.get("kind")
        metadata = document.get("metadata")
        if (
            kind == "ConfigMap"
            and isinstance(metadata, Mapping)
            and metadata.get("name") == "aws-auth"
            and metadata.get("namespace") == "kube-system"
        ):
            diagnostics.append(
                _diagnostic(
                    code="eks_aws_auth_unsupported",
                    message=(
                        "Legacy EKS aws-auth mappings can create authorization paths but "
                        "are unsupported."
                    ),
                    file=file,
                    document=document_index,
                    path="metadata.name",
                    value=metadata,
                    key="name",
                    anchors=(),
                )
            )
            continue
        if kind not in _KINDS:
            continue
        if document.get("apiVersion") != _API_VERSION:
            diagnostics.append(
                _diagnostic(
                    code="rbac_api_version_unsupported",
                    message="Only rbac.authorization.k8s.io/v1 is supported.",
                    file=file,
                    document=document_index,
                    path="apiVersion",
                    value=document,
                    key="apiVersion",
                    anchors=(file, str(kind)),
                )
            )
            continue
        identity = _identity(document)
        if identity is None:
            diagnostics.append(
                _diagnostic(
                    code="rbac_identity_invalid",
                    message="RBAC object requires a concrete kind and metadata.name.",
                    file=file,
                    document=document_index,
                    path="metadata",
                    value=document,
                    key="metadata",
                    anchors=(file, str(kind)),
                )
            )
            continue
        parsed_kind, name, namespace = identity
        if parsed_kind in {"Role", "ClusterRole"}:
            role, found = _extract_role(
                document,
                file=file,
                document_index=document_index,
                kind=parsed_kind,
                name=name,
                namespace=namespace,
            )
            diagnostics.extend(found)
            if role is not None:
                roles.append(role)
        else:
            binding, found = _extract_binding(
                document,
                file=file,
                document_index=document_index,
                kind=parsed_kind,
                name=name,
                namespace=namespace,
            )
            diagnostics.extend(found)
            if binding is not None:
                bindings.append(binding)

    return KubernetesExtraction(
        roles=tuple(sorted(set(roles))),
        bindings=tuple(sorted(set(bindings))),
        diagnostics=tuple(sorted(set(diagnostics))),
    )
