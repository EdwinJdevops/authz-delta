"""Deterministic human-readable rendering for analyzer reports."""

from __future__ import annotations

from collections.abc import Mapping


def _records(report: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    value = report.get(key, [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Mapping[str, object]) -> str:
    """Render a stable review report without interpreting authorization semantics."""
    lines = [
        "# AuthZ Delta report",
        "",
        f"- Analysis status: `{_text(report.get('analysis_status', 'unknown'))}`",
        f"- Schema version: `{_text(report.get('schema_version', 'unknown'))}`",
    ]
    if "repository" in report:
        lines.append(f"- Repository: `{_text(report['repository'])}`")

    lines.extend(["", "## Findings", ""])
    findings = _records(report, "newly_reachable")
    if not findings:
        lines.append("No newly reachable capabilities were proven.")
    else:
        lines.extend(
            [
                "| Finding | Workflow | Job | Cluster | Scope | API group | Resource | Verb |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            lines.append(
                "| "
                + " | ".join(
                    _text(finding.get(field, ""))
                    for field in (
                        "finding_id",
                        "workflow",
                        "job",
                        "cluster",
                        "scope",
                        "api_group",
                        "resource",
                        "verb",
                    )
                )
                + " |"
            )

    lines.extend(["", "## Diagnostics", ""])
    diagnostics = _records(report, "diagnostics")
    if not diagnostics:
        lines.append("No diagnostics.")
    else:
        for diagnostic in diagnostics:
            lines.append(
                "- **"
                + _text(diagnostic.get("code", "unknown"))
                + "** (`"
                + _text(diagnostic.get("state", "unknown"))
                + "`): "
                + _text(diagnostic.get("message", ""))
            )

    lines.extend(["", "## Limitations", ""])
    limitations = report.get("limitations", [])
    if isinstance(limitations, list) and limitations:
        lines.extend(f"- {_text(item)}" for item in limitations)
    else:
        lines.append("No limitations were reported.")
    return "\n".join(lines) + "\n"
