"""Conservative extraction from Terraform/OpenTofu JSON plans."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ..facts import EKSAccessEntry, IAMRoleTrust, IAMSubjectConstraint
from ..iam_strings import matches
from ..model import Diagnostic, ResultState, SourceLocation

_OIDC_PROVIDER_SUFFIX = ":oidc-provider/token.actions.githubusercontent.com"
_AUDIENCE_KEY = "token.actions.githubusercontent.com:aud"
_SUBJECT_KEY = "token.actions.githubusercontent.com:sub"
_SUPPORTED_OPERATORS = frozenset({"StringEquals", "StringLike"})


@dataclass(frozen=True)
class TerraformExtraction:
    """Supported plan facts plus unresolved semantics."""

    role_trusts: tuple[IAMRoleTrust, ...]
    access_entries: tuple[EKSAccessEntry, ...]
    diagnostics: tuple[Diagnostic, ...]


def _source(file: str, address: str, suffix: str = "") -> SourceLocation:
    path = address if not suffix else f"{address}.{suffix}"
    return SourceLocation(file=file, path=path)


def _diagnostic(
    *,
    code: str,
    message: str,
    file: str,
    address: str,
    anchors: Iterable[str],
    suffix: str = "",
) -> Diagnostic:
    return Diagnostic(
        code=code,
        state=ResultState.INDETERMINATE,
        message=message,
        anchors=tuple(sorted(set(anchors))),
        evidence=(_source(file, address, suffix),),
    )


def _as_strings(value: object) -> tuple[str, ...] | None:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, str) and item for item in values):
        return None
    return tuple(sorted(set(values)))


def _walk_module(module: object) -> Iterable[Mapping[str, object]]:
    if not isinstance(module, Mapping):
        return
    resources = module.get("resources", [])
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, Mapping):
                yield resource
    children = module.get("child_modules", [])
    if isinstance(children, list):
        for child in children:
            yield from _walk_module(child)


def _change_maps(plan: Mapping[str, object]) -> dict[str, tuple[object, object]]:
    result: dict[str, tuple[object, object]] = {}
    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        return result
    for resource in changes:
        if not isinstance(resource, Mapping):
            continue
        address = resource.get("address")
        change = resource.get("change")
        if not isinstance(address, str) or not isinstance(change, Mapping):
            continue
        result[address] = (change.get("after_unknown", {}), change.get("after_sensitive", {}))
    return result


def _has_unknown(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        return any(_has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_unknown(item) for item in value)
    return False


def _field_unavailable(
    *,
    field: str,
    value: object,
    unknown: object,
    sensitive: object,
    file: str,
    address: str,
    anchors: tuple[str, ...],
) -> Diagnostic | None:
    unknown_value = unknown.get(field) if isinstance(unknown, Mapping) else unknown
    sensitive_value = sensitive.get(field) if isinstance(sensitive, Mapping) else None
    if _has_unknown(unknown_value):
        return _diagnostic(
            code="terraform_value_unknown",
            message=f"Terraform value {field} is unknown in the planned state.",
            file=file,
            address=address,
            suffix=field,
            anchors=anchors,
        )
    if value is None and sensitive_value is True:
        return _diagnostic(
            code="terraform_sensitive_value_not_concrete",
            message=f"Terraform value {field} is sensitive and has no concrete planned value.",
            file=file,
            address=address,
            suffix=field,
            anchors=anchors,
        )
    if value is None:
        return _diagnostic(
            code="terraform_value_absent",
            message=f"Terraform value {field} has no concrete planned value.",
            file=file,
            address=address,
            suffix=field,
            anchors=anchors,
        )
    return None


def _relevant_statement(statement: Mapping[str, object]) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    actions = _as_strings(statement.get("Action"))
    if actions is None or "sts:AssumeRoleWithWebIdentity" not in actions:
        return False
    principal = statement.get("Principal")
    if not isinstance(principal, Mapping):
        return False
    providers = _as_strings(principal.get("Federated"))
    return providers is not None and any(
        provider.endswith(_OIDC_PROVIDER_SUFFIX) for provider in providers
    )


def _statement_subjects(
    statement: Mapping[str, object],
    *,
    file: str,
    address: str,
    role_arn: str,
) -> tuple[tuple[IAMSubjectConstraint, ...], tuple[Diagnostic, ...]]:
    condition = statement.get("Condition", {})
    if not isinstance(condition, Mapping):
        return (), (
            _diagnostic(
                code="iam_condition_invalid",
                message="IAM trust Condition must be an object.",
                file=file,
                address=address,
                suffix="assume_role_policy",
                anchors=(address, role_arn),
            ),
        )
    unsupported_operators = sorted(
        str(operator) for operator in condition if operator not in _SUPPORTED_OPERATORS
    )
    if unsupported_operators:
        return (), (
            _diagnostic(
                code="iam_condition_operator_unsupported",
                message=(
                    "IAM trust uses unsupported condition operator(s): "
                    f"{', '.join(unsupported_operators)}."
                ),
                file=file,
                address=address,
                suffix="assume_role_policy",
                anchors=(address, role_arn),
            ),
        )

    audience_constraints: list[tuple[str, tuple[str, ...]]] = []
    subject_constraints: list[tuple[str, tuple[str, ...]]] = []
    for operator, raw_terms in condition.items():
        if not isinstance(raw_terms, Mapping):
            return (), (
                _diagnostic(
                    code="iam_condition_invalid",
                    message=f"IAM {operator} condition must be an object.",
                    file=file,
                    address=address,
                    suffix="assume_role_policy",
                    anchors=(address, role_arn),
                ),
            )
        unexpected_keys = sorted(
            str(key) for key in raw_terms if key not in {_AUDIENCE_KEY, _SUBJECT_KEY}
        )
        if unexpected_keys:
            return (), (
                _diagnostic(
                    code="iam_condition_key_unsupported",
                    message=(
                        "IAM trust uses unsupported condition key(s): "
                        f"{', '.join(unexpected_keys)}."
                    ),
                    file=file,
                    address=address,
                    suffix="assume_role_policy",
                    anchors=(address, role_arn),
                ),
            )
        if _AUDIENCE_KEY in raw_terms:
            values = _as_strings(raw_terms[_AUDIENCE_KEY])
            if values is None:
                return (), (
                    _diagnostic(
                        code="iam_condition_value_invalid",
                        message="IAM audience condition must contain string values.",
                        file=file,
                        address=address,
                        suffix="assume_role_policy",
                        anchors=(address, role_arn),
                    ),
                )
            audience_constraints.append((str(operator), values))
        if _SUBJECT_KEY in raw_terms:
            values = _as_strings(raw_terms[_SUBJECT_KEY])
            if values is None:
                return (), (
                    _diagnostic(
                        code="iam_condition_value_invalid",
                        message="IAM subject condition must contain string values.",
                        file=file,
                        address=address,
                        suffix="assume_role_policy",
                        anchors=(address, role_arn),
                    ),
                )
            subject_constraints.append((str(operator), values))

    if not all(
        any(matches("sts.amazonaws.com", operator, value) for value in values)
        for operator, values in audience_constraints
    ):
        return (), ()
    if len(subject_constraints) > 1:
        return (), (
            _diagnostic(
                code="iam_multiple_subject_conditions_unsupported",
                message="Multiple IAM subject conditions cannot be reduced without evaluation.",
                file=file,
                address=address,
                suffix="assume_role_policy",
                anchors=(address, role_arn),
            ),
        )
    if not subject_constraints:
        return (IAMSubjectConstraint(operator="StringLike", value="*"),), ()
    operator, values = subject_constraints[0]
    return tuple(IAMSubjectConstraint(operator=operator, value=value) for value in values), ()


def _extract_role(
    *,
    values: Mapping[str, object],
    unknown: object,
    sensitive: object,
    file: str,
    address: str,
) -> tuple[IAMRoleTrust | None, tuple[Diagnostic, ...]]:
    role_raw = values.get("arn")
    policy_raw = values.get("assume_role_policy")
    anchors = (address,) + ((role_raw,) if isinstance(role_raw, str) else ())
    diagnostics = [
        item
        for field, value in (("arn", role_raw), ("assume_role_policy", policy_raw))
        if (
            item := _field_unavailable(
                field=field,
                value=value,
                unknown=unknown,
                sensitive=sensitive,
                file=file,
                address=address,
                anchors=anchors,
            )
        )
        is not None
    ]
    if diagnostics:
        return None, tuple(diagnostics)
    if not isinstance(role_raw, str) or not role_raw or not isinstance(policy_raw, str):
        return None, (
            _diagnostic(
                code="terraform_value_invalid",
                message="IAM role ARN and trust policy must be concrete strings.",
                file=file,
                address=address,
                anchors=anchors,
            ),
        )
    try:
        policy = json.loads(policy_raw)
    except json.JSONDecodeError as error:
        return None, (
            _diagnostic(
                code="iam_trust_policy_invalid",
                message=f"IAM trust policy is not valid JSON: {error.msg}.",
                file=file,
                address=address,
                suffix="assume_role_policy",
                anchors=anchors,
            ),
        )
    if not isinstance(policy, Mapping):
        return None, (
            _diagnostic(
                code="iam_trust_policy_invalid",
                message="IAM trust policy root must be an object.",
                file=file,
                address=address,
                suffix="assume_role_policy",
                anchors=anchors,
            ),
        )
    raw_statements = policy.get("Statement")
    statements = raw_statements if isinstance(raw_statements, list) else [raw_statements]
    constraints: set[IAMSubjectConstraint] = set()
    policy_diagnostics: list[Diagnostic] = []
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") not in {"Allow", "Deny"}:
            policy_diagnostics.append(
                _diagnostic(
                    code="iam_statement_invalid",
                    message="IAM trust statement is malformed.",
                    file=file,
                    address=address,
                    anchors=anchors,
                    suffix="assume_role_policy",
                )
            )
            continue
        # Until deny conditions are evaluated completely, no allow in this role is proven.
        if statement.get("Effect") == "Deny":
            policy_diagnostics.append(
                _diagnostic(
                    code="iam_deny_not_evaluated",
                    message="Trust contains a Deny statement; its effect is not evaluated.",
                    file=file,
                    address=address,
                    anchors=anchors,
                    suffix="assume_role_policy",
                )
            )
            continue
        if "NotAction" in statement or "NotPrincipal" in statement:
            policy_diagnostics.append(
                _diagnostic(
                    code="iam_statement_unsupported",
                    message="NotAction and NotPrincipal trust statements are unsupported.",
                    file=file,
                    address=address,
                    anchors=anchors,
                    suffix="assume_role_policy",
                )
            )
            continue
        if not _relevant_statement(statement):
            continue
        subjects, statement_diagnostics = _statement_subjects(
            statement, file=file, address=address, role_arn=role_raw
        )
        constraints.update(subjects)
        policy_diagnostics.extend(statement_diagnostics)
    if policy_diagnostics:
        return None, tuple(sorted(set(policy_diagnostics)))
    if not constraints:
        return None, ()
    return (
        IAMRoleTrust(
            role_arn=role_raw,
            subject_constraints=tuple(sorted(constraints)),
            evidence=(_source(file, address, "assume_role_policy"),),
        ),
        (),
    )


def _extract_access_entry(
    *,
    values: Mapping[str, object],
    unknown: object,
    sensitive: object,
    file: str,
    address: str,
) -> tuple[EKSAccessEntry | None, tuple[Diagnostic, ...]]:
    cluster = values.get("cluster_name")
    role = values.get("principal_arn")
    groups_raw = values.get("kubernetes_groups")
    anchors = (address,) + tuple(item for item in (cluster, role) if isinstance(item, str) and item)
    diagnostics = [
        item
        for field, value in (
            ("cluster_name", cluster),
            ("principal_arn", role),
            ("kubernetes_groups", groups_raw),
        )
        if (
            item := _field_unavailable(
                field=field,
                value=value,
                unknown=unknown,
                sensitive=sensitive,
                file=file,
                address=address,
                anchors=anchors,
            )
        )
        is not None
    ]
    if diagnostics:
        return None, tuple(diagnostics)
    groups = _as_strings(groups_raw)
    if not isinstance(cluster, str) or not cluster or not isinstance(role, str) or not role:
        return None, (
            _diagnostic(
                code="terraform_value_invalid",
                message="EKS access entry cluster and principal ARN must be concrete strings.",
                file=file,
                address=address,
                anchors=anchors,
            ),
        )
    if groups_raw == []:
        return None, ()
    if groups is None:
        return None, (
            _diagnostic(
                code="terraform_value_invalid",
                message="EKS kubernetes_groups must be an array of non-empty strings.",
                file=file,
                address=address,
                suffix="kubernetes_groups",
                anchors=anchors,
            ),
        )
    return (
        EKSAccessEntry(
            role_arn=role,
            cluster=cluster,
            groups=groups,
            evidence=(_source(file, address),),
        ),
        (),
    )


def extract_terraform_plan(path: Path, *, display_path: str | None = None) -> TerraformExtraction:
    """Extract supported IAM and EKS facts from a plan JSON document."""
    file = display_path or path.as_posix()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return TerraformExtraction(
            role_trusts=(),
            access_entries=(),
            diagnostics=(
                Diagnostic(
                    code="terraform_plan_read_error",
                    state=ResultState.INDETERMINATE,
                    message=f"Cannot read Terraform JSON plan: {error}.",
                    anchors=(file,),
                    evidence=(SourceLocation(file=file),),
                ),
            ),
        )
    if not isinstance(raw, Mapping):
        return TerraformExtraction(
            role_trusts=(),
            access_entries=(),
            diagnostics=(
                Diagnostic(
                    code="terraform_plan_invalid",
                    state=ResultState.INDETERMINATE,
                    message="Terraform JSON plan root must be an object.",
                    anchors=(file,),
                    evidence=(SourceLocation(file=file),),
                ),
            ),
        )
    planned = raw.get("planned_values")
    root = planned.get("root_module") if isinstance(planned, Mapping) else None
    if not isinstance(root, Mapping):
        return TerraformExtraction(
            role_trusts=(),
            access_entries=(),
            diagnostics=(
                Diagnostic(
                    code="terraform_planned_values_absent",
                    state=ResultState.INDETERMINATE,
                    message="Terraform plan does not contain planned_values.root_module.",
                    anchors=(file,),
                    evidence=(SourceLocation(file=file, path="planned_values.root_module"),),
                ),
            ),
        )

    changes = _change_maps(raw)
    trusts: list[IAMRoleTrust] = []
    entries: list[EKSAccessEntry] = []
    diagnostics: list[Diagnostic] = []
    for resource in _walk_module(root):
        address = resource.get("address")
        resource_type = resource.get("type")
        values = resource.get("values")
        if isinstance(address, str) and resource_type == "aws_eks_access_policy_association":
            anchors = [address]
            if isinstance(values, Mapping):
                anchors.extend(
                    value
                    for value in (values.get("cluster_name"), values.get("principal_arn"))
                    if isinstance(value, str) and value
                )
            diagnostics.append(
                _diagnostic(
                    code="eks_access_policy_association_unsupported",
                    message=(
                        "EKS access-policy associations grant permissions outside the "
                        "kubernetes_groups path."
                    ),
                    file=file,
                    address=address,
                    anchors=anchors,
                )
            )
            continue
        if not isinstance(address, str) or resource_type not in {
            "aws_iam_role",
            "aws_eks_access_entry",
        }:
            continue
        if not isinstance(values, Mapping):
            diagnostics.append(
                _diagnostic(
                    code="terraform_resource_values_invalid",
                    message="Terraform resource values must be an object.",
                    file=file,
                    address=address,
                    anchors=(address,),
                )
            )
            continue
        unknown, sensitive = changes.get(address, ({}, {}))
        if resource_type == "aws_iam_role":
            trust, found = _extract_role(
                values=values,
                unknown=unknown,
                sensitive=sensitive,
                file=file,
                address=address,
            )
            diagnostics.extend(found)
            if trust is not None:
                trusts.append(trust)
        else:
            entry, found = _extract_access_entry(
                values=values,
                unknown=unknown,
                sensitive=sensitive,
                file=file,
                address=address,
            )
            diagnostics.extend(found)
            if entry is not None:
                entries.append(entry)

    return TerraformExtraction(
        role_trusts=tuple(sorted(set(trusts))),
        access_entries=tuple(sorted(set(entries))),
        diagnostics=tuple(sorted(set(diagnostics))),
    )
