"""Command line entrypoint for the normalized-fact delta core."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from .builder import build_revision
from .diff import compare_snapshots
from .model import Snapshot
from .render import render_markdown


def _load_snapshot(path: Path) -> Snapshot:
    raw = path.read_bytes()
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error.msg}") from error

    return Snapshot.from_mapping(decoded)


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="authz-delta")
    subparsers = parser.add_subparsers(dest="command", required=True)
    compare = subparsers.add_parser("compare", help="compare two normalized fact snapshots")
    compare.add_argument("--before", type=Path, required=True)
    compare.add_argument("--after", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    compare.add_argument("--format", choices=("json", "markdown"), default="json")

    analyze = subparsers.add_parser("analyze", help="analyze and compare two repository inputs")
    analyze.add_argument("--repository", required=True, help="literal GitHub owner/name")
    for revision in ("before", "after"):
        analyze.add_argument(
            f"--{revision}-oidc-subject-prefix",
            help="Caller-verified repo:owner/name or repo:owner@ID/name@ID subject prefix",
        )
    analyze.add_argument("--before-root", type=Path, required=True)
    analyze.add_argument("--before-plan", type=Path, required=True)
    analyze.add_argument("--before-rbac", type=Path, action="append", required=True)
    analyze.add_argument("--after-root", type=Path, required=True)
    analyze.add_argument("--after-plan", type=Path, required=True)
    analyze.add_argument("--after-rbac", type=Path, action="append", required=True)
    analyze.add_argument("--output", type=Path, required=True)
    analyze.add_argument("--format", choices=("json", "markdown"), default="json")
    return parser


def _compare_normalized(args: argparse.Namespace) -> dict[str, object]:
    try:
        before = _load_snapshot(args.before)
        after = _load_snapshot(args.after)
    except (OSError, ValueError) as error:
        raise SystemExit(f"input error: {error}") from error

    delta = compare_snapshots(before, after)
    return {
        "schema_version": "0.2",
        "analysis_status": (
            "indeterminate" if delta.diagnostics else "proven_for_normalized_snapshot_only"
        ),
        "limitations": [
            "This command compares already-normalized facts.",
            "It does not parse Terraform, GitHub Actions, or Kubernetes manifests yet.",
            "It does not calculate AWS effective permissions or runtime authorization.",
        ],
        "before_sha256": _hash(args.before),
        "after_sha256": _hash(args.after),
        "newly_reachable": [item.to_mapping() for item in delta.newly_reachable],
        "removed": [item.to_mapping() for item in delta.removed],
        "diagnostics": [item.to_mapping() for item in delta.diagnostics],
    }


def _analyze(args: argparse.Namespace) -> dict[str, object]:
    try:
        before = build_revision(
            repository=args.repository,
            oidc_subject_prefix=args.before_oidc_subject_prefix,
            root=args.before_root,
            plan=args.before_plan,
            rbac_inputs=tuple(args.before_rbac),
        )
        after = build_revision(
            repository=args.repository,
            oidc_subject_prefix=args.after_oidc_subject_prefix,
            root=args.after_root,
            plan=args.after_plan,
            rbac_inputs=tuple(args.after_rbac),
        )
    except ValueError as error:
        raise SystemExit(f"input error: {error}") from error
    delta = compare_snapshots(before.snapshot, after.snapshot)
    return {
        "schema_version": "0.2",
        "analysis_status": (
            "indeterminate" if delta.diagnostics else "proven_within_supported_static_inputs"
        ),
        "repository": args.repository,
        "oidc_subject_prefixes": {
            "before": args.before_oidc_subject_prefix,
            "after": args.after_oidc_subject_prefix,
        },
        "assumptions": [
            "Caller-supplied subject prefixes reflect each revision's GitHub OIDC settings.",
            "GitHub uses an environment-based template without additional custom claims.",
            "OIDC audience is sts.amazonaws.com; custom action audiences are unsupported.",
            "Supplied RBAC manifests belong to the single relevant EKS cluster.",
            "Revision identity is supplied by the caller, without Git or live-state attestation.",
        ],
        "before_input_sha256": before.input_sha256,
        "after_input_sha256": after.input_sha256,
        "limitations": [
            "Results describe only the supported static repository inputs.",
            "Results are not AWS effective permissions or Kubernetes runtime authorization.",
            "Any raw-input diagnostic suppresses all deltas until its relevance can be proven.",
            (
                "Live cloud state, generated configuration, and unsupported mechanisms "
                "are not inferred."
            ),
        ],
        "newly_reachable": [item.to_mapping() for item in delta.newly_reachable],
        "removed": [item.to_mapping() for item in delta.removed],
        "diagnostics": [item.to_mapping() for item in delta.diagnostics],
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = _compare_normalized(args) if args.command == "compare" else _analyze(args)
    rendered = (
        json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else render_markdown(report)
    )
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
