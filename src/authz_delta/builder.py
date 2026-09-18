"""Repository input discovery and revision snapshot construction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

from .extractors.github import extract_workflow
from .extractors.kubernetes import extract_rbac
from .extractors.terraform import extract_terraform_plan
from .facts import EKSAccessEntry, IAMRoleTrust, RBACBinding, RBACRole, WorkflowRoleRequest
from .graph import build_snapshot
from .model import Diagnostic, ResultState, Snapshot, SourceLocation


@dataclass(frozen=True)
class RevisionBuild:
    """One analyzed revision and the digest of every consumed input."""

    snapshot: Snapshot
    input_sha256: str


def _display(path: Path, root: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _rbac_files(paths: tuple[Path, ...]) -> tuple[Path, ...]:
    files: set[Path] = set()
    for path in paths:
        if path.is_dir():
            files.update(path.rglob("*.yaml"))
            files.update(path.rglob("*.yml"))
        else:
            files.add(path)
    return tuple(sorted(files, key=lambda item: item.as_posix()))


def _digest(files: tuple[tuple[str, Path], ...]) -> str:
    digest = hashlib.sha256()
    for label, path in sorted(files, key=lambda item: item[0]):
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
        digest.update(b"\0")
    return digest.hexdigest()


def build_revision(
    *,
    repository: str,
    oidc_subject_prefix: str | None = None,
    root: Path,
    plan: Path,
    rbac_inputs: tuple[Path, ...],
) -> RevisionBuild:
    """Build one immutable snapshot from explicit offline inputs."""
    diagnostics: list[Diagnostic] = []
    workflows: list[WorkflowRoleRequest] = []
    trusts: list[IAMRoleTrust] = []
    entries: list[EKSAccessEntry] = []
    roles: list[RBACRole] = []
    bindings: list[RBACBinding] = []
    consumed: list[tuple[str, Path]] = []

    workflow_directory = root / ".github" / "workflows"
    workflow_files = tuple(
        sorted(
            set(workflow_directory.glob("*.yml")).union(workflow_directory.glob("*.yaml")),
            key=lambda item: item.as_posix(),
        )
    )
    if not workflow_files:
        diagnostics.append(
            Diagnostic(
                code="github_workflows_absent",
                state=ResultState.INDETERMINATE,
                message="No workflow YAML files were found in .github/workflows.",
                anchors=(root.as_posix(),),
                evidence=(SourceLocation(file=".github/workflows"),),
            )
        )
    for workflow_path in workflow_files:
        display = _display(workflow_path, root)
        consumed.append((display, workflow_path))
        if workflow_path.is_symlink():
            diagnostics.append(
                Diagnostic(
                    code="input_symlink_unsupported",
                    state=ResultState.INDETERMINATE,
                    message="Symlinked workflow inputs are not followed.",
                    anchors=(display,),
                    evidence=(SourceLocation(file=display),),
                )
            )
            continue
        workflow_result = extract_workflow(workflow_path, display_path=display)
        workflows.extend(workflow_result.role_requests)
        diagnostics.extend(workflow_result.diagnostics)

    plan_display = _display(plan, root)
    consumed.append((plan_display, plan))
    plan_result = extract_terraform_plan(plan, display_path=plan_display)
    trusts.extend(plan_result.role_trusts)
    entries.extend(plan_result.access_entries)
    diagnostics.extend(plan_result.diagnostics)

    rbac_files = _rbac_files(rbac_inputs)
    if not rbac_files:
        diagnostics.append(
            Diagnostic(
                code="rbac_inputs_absent",
                state=ResultState.INDETERMINATE,
                message="No Kubernetes YAML files were found in the supplied RBAC inputs.",
                anchors=(root.as_posix(),),
            )
        )
    for rbac_path in rbac_files:
        display = _display(rbac_path, root)
        consumed.append((display, rbac_path))
        if rbac_path.is_symlink():
            diagnostics.append(
                Diagnostic(
                    code="input_symlink_unsupported",
                    state=ResultState.INDETERMINATE,
                    message="Symlinked RBAC inputs are not followed.",
                    anchors=(display,),
                    evidence=(SourceLocation(file=display),),
                )
            )
            continue
        rbac_result = extract_rbac(rbac_path, display_path=display)
        roles.extend(rbac_result.roles)
        bindings.extend(rbac_result.bindings)
        diagnostics.extend(rbac_result.diagnostics)

    snapshot = build_snapshot(
        repository=repository,
        oidc_subject_prefix=oidc_subject_prefix,
        workflows=tuple(sorted(set(workflows))),
        role_trusts=tuple(sorted(set(trusts))),
        access_entries=tuple(sorted(set(entries))),
        roles=tuple(sorted(set(roles))),
        bindings=tuple(sorted(set(bindings))),
        diagnostics=tuple(sorted(set(diagnostics))),
    )
    # File/resource labels are not a proof of diagnostic irrelevance. Until dependency
    # tracking is complete, uncertainty in raw inputs blocks all deltas for this revision.
    if snapshot.diagnostics:
        snapshot = replace(
            snapshot,
            capabilities=frozenset(),
            diagnostics=tuple(sorted({replace(item, anchors=()) for item in snapshot.diagnostics})),
        )
    return RevisionBuild(snapshot=snapshot, input_sha256=_digest(tuple(consumed)))
