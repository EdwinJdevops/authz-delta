"""Set-based reachability delta computation."""

from __future__ import annotations

from dataclasses import dataclass

from .model import Capability, Diagnostic, ResultState, Snapshot


@dataclass(frozen=True)
class Delta:
    """Deterministic comparison result."""

    newly_reachable: tuple[Capability, ...]
    removed: tuple[Capability, ...]
    diagnostics: tuple[Diagnostic, ...]


def new_capabilities(before: set[Capability], after: set[Capability]) -> list[Capability]:
    """Return the deterministic set difference for complete capability paths."""
    return sorted(after.difference(before))


def compare_snapshots(before: Snapshot, after: Snapshot) -> Delta:
    """Compare snapshots without upgrading uncertainty into a finding."""
    before_by_identity = {item.identity: item for item in before.capabilities}
    after_by_identity = {item.identity: item for item in after.capabilities}
    candidates = [
        item for identity, item in after_by_identity.items() if identity not in before_by_identity
    ]
    removal_candidates = tuple(
        sorted(
            item
            for identity, item in before_by_identity.items()
            if identity not in after_by_identity
        )
    )

    inherited_diagnostics = tuple(sorted(set(before.diagnostics).union(after.diagnostics)))
    findings: list[Capability] = []
    removed: list[Capability] = []
    delta_diagnostics: list[Diagnostic] = []
    for candidate in sorted(candidates):
        blockers = [item for item in inherited_diagnostics if item.affects(candidate)]
        if blockers:
            delta_diagnostics.append(
                Diagnostic(
                    code="indeterminate_delta",
                    state=ResultState.INDETERMINATE,
                    message=(
                        f"Cannot prove {candidate.finding_id} is newly reachable because "
                        "a relevant unsupported or unresolved input exists."
                    ),
                    anchors=tuple(sorted(candidate.anchors)),
                    evidence=candidate.evidence,
                )
            )
            continue
        findings.append(candidate)

    for candidate in removal_candidates:
        if any(item.affects(candidate) for item in inherited_diagnostics):
            delta_diagnostics.append(
                Diagnostic(
                    code="indeterminate_removal",
                    state=ResultState.INDETERMINATE,
                    message=(
                        f"Cannot prove {candidate.finding_id} was removed due to unresolved inputs."
                    ),
                    anchors=tuple(sorted(candidate.anchors)),
                    evidence=candidate.evidence,
                )
            )
        else:
            removed.append(candidate)

    return Delta(
        newly_reachable=tuple(findings),
        removed=tuple(removed),
        diagnostics=tuple(sorted(set(inherited_diagnostics).union(delta_diagnostics))),
    )
