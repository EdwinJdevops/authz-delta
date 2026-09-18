"""Conservative GitHub Actions workflow extraction."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.error import YAMLError

from ..facts import WorkflowRoleRequest
from ..model import Diagnostic, ResultState, SourceLocation

_CONFIGURE_AWS = re.compile(r"^aws-actions/configure-aws-credentials@[^\s]+$")
_MAX_WORKFLOW_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class GitHubExtraction:
    """Facts and diagnostics obtained from one workflow file."""

    role_requests: tuple[WorkflowRoleRequest, ...]
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


def _source(file: str, path: str, value: object, key: object | None = None) -> SourceLocation:
    return SourceLocation(file=file, path=path, line=_line(value, key))


def _diagnostic(
    *,
    code: str,
    state: ResultState,
    message: str,
    file: str,
    path: str,
    value: object,
    anchors: tuple[str, ...],
    key: object | None = None,
) -> Diagnostic:
    return Diagnostic(
        code=code,
        state=state,
        message=message,
        anchors=tuple(sorted(set(anchors))),
        evidence=(_source(file, path, value, key),),
    )


def _literal(value: object) -> str | None:
    if not isinstance(value, str) or not value or "${{" in value:
        return None
    return value


def _events(root: Mapping[object, object]) -> tuple[str, ...]:
    value = root.get("on")
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        names = [key for key in value if isinstance(key, str)]
        return tuple(sorted(names))
    return ()


def _id_token_enabled(
    permissions: object,
    *,
    file: str,
    path: str,
    anchors: tuple[str, ...],
) -> tuple[bool, Diagnostic | None]:
    if permissions is None:
        return False, None
    if not isinstance(permissions, Mapping):
        return (
            False,
            _diagnostic(
                code="github_permissions_shorthand_unsupported",
                state=ResultState.INDETERMINATE,
                message="GitHub permissions must use mapping form; shorthand is unsupported.",
                file=file,
                path=path,
                value=permissions,
                anchors=anchors,
            ),
        )
    permission = permissions.get("id-token")
    if isinstance(permission, str) and "${{" in permission:
        return (
            False,
            _diagnostic(
                code="github_expression_unsupported",
                state=ResultState.INDETERMINATE,
                message="Expressions in GitHub permissions are unsupported.",
                file=file,
                path=f"{path}.id-token",
                value=permissions,
                key="id-token",
                anchors=anchors,
            ),
        )
    return permission == "write", None


def _parse_root(
    path: Path, display_path: str
) -> tuple[Mapping[object, object] | None, tuple[Diagnostic, ...]]:
    try:
        raw = path.read_bytes()
    except (OSError, UnicodeError) as error:
        return None, (
            Diagnostic(
                code="workflow_read_error",
                state=ResultState.INDETERMINATE,
                message=f"Cannot read workflow: {error}.",
                anchors=(display_path,),
                evidence=(SourceLocation(file=display_path),),
            ),
        )
    if len(raw) > _MAX_WORKFLOW_BYTES:
        return None, (
            Diagnostic(
                code="workflow_size_limit_exceeded",
                state=ResultState.INDETERMINATE,
                message=(
                    f"Workflow exceeds the {_MAX_WORKFLOW_BYTES} byte parser limit; "
                    "the file was not parsed."
                ),
                anchors=(display_path,),
                evidence=(SourceLocation(file=display_path),),
            ),
        )
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        return None, (
            Diagnostic(
                code="workflow_read_error",
                state=ResultState.INDETERMINATE,
                message=f"Cannot read workflow: {error}.",
                anchors=(display_path,),
                evidence=(SourceLocation(file=display_path),),
            ),
        )

    yaml: Any = YAML(typ="rt", pure=True)
    yaml.allow_duplicate_keys = False
    try:
        root = yaml.load(source)
    except DuplicateKeyError as error:
        return None, (
            Diagnostic(
                code="yaml_duplicate_key",
                state=ResultState.INDETERMINATE,
                message=f"Workflow contains a duplicate YAML key: {error.problem}.",
                anchors=(display_path,),
                evidence=(SourceLocation(file=display_path),),
            ),
        )
    except YAMLError as error:
        problem = getattr(error, "problem", None)
        return None, (
            Diagnostic(
                code="yaml_parse_error",
                state=ResultState.INDETERMINATE,
                message=f"Workflow is not valid YAML: {problem or type(error).__name__}.",
                anchors=(display_path,),
                evidence=(SourceLocation(file=display_path),),
            ),
        )
    if not isinstance(root, Mapping):
        return None, (
            Diagnostic(
                code="workflow_root_invalid",
                state=ResultState.INDETERMINATE,
                message="Workflow root must be a YAML mapping.",
                anchors=(display_path,),
                evidence=(SourceLocation(file=display_path, line=_line(root)),),
            ),
        )
    return root, ()


def extract_workflow(path: Path, *, display_path: str | None = None) -> GitHubExtraction:
    """Extract literal OIDC role requests without evaluating workflow expressions."""
    file = display_path or path.as_posix()
    root, parse_diagnostics = _parse_root(path, file)
    if root is None:
        return GitHubExtraction(role_requests=(), diagnostics=parse_diagnostics)

    diagnostics: list[Diagnostic] = list(parse_diagnostics)
    requests: list[WorkflowRoleRequest] = []
    events = _events(root)
    workflow_permissions = root.get("permissions")
    jobs = root.get("jobs")
    if not isinstance(jobs, Mapping):
        diagnostics.append(
            _diagnostic(
                code="workflow_jobs_invalid",
                state=ResultState.INDETERMINATE,
                message="Workflow jobs must be a YAML mapping.",
                file=file,
                path="jobs",
                value=root,
                key="jobs",
                anchors=(file,),
            )
        )
        return GitHubExtraction((), tuple(sorted(diagnostics)))

    for job_name, raw_job in sorted(jobs.items(), key=lambda item: str(item[0])):
        if not isinstance(job_name, str) or not isinstance(raw_job, Mapping):
            diagnostics.append(
                _diagnostic(
                    code="github_job_invalid",
                    state=ResultState.INDETERMINATE,
                    message="Each GitHub job must have a string identifier and mapping value.",
                    file=file,
                    path="jobs",
                    value=jobs,
                    key=job_name,
                    anchors=(file,),
                )
            )
            continue
        anchors = (file, job_name)
        job_path = f"jobs.{job_name}"
        if "uses" in raw_job:
            diagnostics.append(
                _diagnostic(
                    code="github_reusable_workflow_unsupported",
                    state=ResultState.INDETERMINATE,
                    message="Reusable workflow calls are unsupported.",
                    file=file,
                    path=f"{job_path}.uses",
                    value=raw_job,
                    key="uses",
                    anchors=anchors,
                )
            )
            continue
        strategy = raw_job.get("strategy")
        if isinstance(strategy, Mapping) and "matrix" in strategy:
            diagnostics.append(
                _diagnostic(
                    code="github_matrix_unsupported",
                    state=ResultState.INDETERMINATE,
                    message="GitHub job matrices are unsupported.",
                    file=file,
                    path=f"{job_path}.strategy.matrix",
                    value=strategy,
                    key="matrix",
                    anchors=anchors,
                )
            )
            continue

        permissions = raw_job.get("permissions", workflow_permissions)
        has_id_token, permission_diagnostic = _id_token_enabled(
            permissions,
            file=file,
            path=f"{job_path}.permissions",
            anchors=anchors,
        )
        if permission_diagnostic is not None:
            diagnostics.append(permission_diagnostic)

        environment_raw = raw_job.get("environment")
        environment = _literal(environment_raw) if environment_raw is not None else None
        if environment_raw is not None and environment is None:
            diagnostics.append(
                _diagnostic(
                    code="github_environment_unsupported",
                    state=ResultState.INDETERMINATE,
                    message="Only literal scalar GitHub environments are supported.",
                    file=file,
                    path=f"{job_path}.environment",
                    value=raw_job,
                    key="environment",
                    anchors=anchors,
                )
            )
            continue

        steps = raw_job.get("steps", [])
        if not isinstance(steps, list):
            diagnostics.append(
                _diagnostic(
                    code="github_steps_invalid",
                    state=ResultState.INDETERMINATE,
                    message="GitHub job steps must be an array.",
                    file=file,
                    path=f"{job_path}.steps",
                    value=raw_job,
                    key="steps",
                    anchors=anchors,
                )
            )
            continue

        for index, step in enumerate(steps):
            if not isinstance(step, Mapping):
                continue
            uses = step.get("uses")
            step_path = f"{job_path}.steps[{index}]"
            if isinstance(uses, str) and uses.startswith("./"):
                diagnostics.append(
                    _diagnostic(
                        code="github_composite_action_unsupported",
                        state=ResultState.INDETERMINATE,
                        message="Local or composite actions are unsupported.",
                        file=file,
                        path=f"{step_path}.uses",
                        value=step,
                        key="uses",
                        anchors=anchors,
                    )
                )
                continue
            if not isinstance(uses, str) or _CONFIGURE_AWS.fullmatch(uses) is None:
                continue
            if not has_id_token:
                diagnostics.append(
                    _diagnostic(
                        code="github_id_token_not_enabled",
                        state=ResultState.NOT_EVALUATED,
                        message="The job does not grant literal id-token: write permission.",
                        file=file,
                        path=f"{step_path}.uses",
                        value=step,
                        key="uses",
                        anchors=anchors,
                    )
                )
                continue
            inputs = step.get("with")
            if isinstance(inputs, Mapping) and (
                set(inputs).difference({"role-to-assume", "aws-region", "audience"})
                or inputs.get("audience", "sts.amazonaws.com") != "sts.amazonaws.com"
            ):
                diagnostics.append(
                    _diagnostic(
                        code="github_credential_options_unsupported",
                        state=ResultState.INDETERMINATE,
                        message="Credential action options exceed the supported default OIDC path.",
                        file=file,
                        path=f"{step_path}.with",
                        value=step,
                        key="with",
                        anchors=anchors,
                    )
                )
                continue
            role_raw = inputs.get("role-to-assume") if isinstance(inputs, Mapping) else None
            role = _literal(role_raw)
            if role is None:
                diagnostics.append(
                    _diagnostic(
                        code=(
                            "github_expression_unsupported"
                            if isinstance(role_raw, str) and "${{" in role_raw
                            else "github_role_to_assume_missing"
                        ),
                        state=ResultState.INDETERMINATE,
                        message="role-to-assume must be a literal non-empty string.",
                        file=file,
                        path=f"{step_path}.with.role-to-assume",
                        value=inputs if isinstance(inputs, Mapping) else step,
                        key="role-to-assume" if isinstance(inputs, Mapping) else "with",
                        anchors=anchors,
                    )
                )
                continue
            requests.append(
                WorkflowRoleRequest(
                    workflow=file,
                    job=job_name,
                    role_arn=role,
                    events=events,
                    environment=environment,
                    evidence=(_source(file, f"{step_path}.uses", step, "uses"),),
                )
            )

    return GitHubExtraction(
        role_requests=tuple(sorted(set(requests))),
        diagnostics=tuple(sorted(set(diagnostics))),
    )
