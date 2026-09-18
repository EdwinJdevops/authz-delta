import json
from pathlib import Path

from authz_delta.cli import main


def write_revision(root: Path, *, verbs: list[str]) -> tuple[Path, Path]:
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "deploy.yml").write_text(
        """
on: push
permissions:
  id-token: write
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deployer
""",
        encoding="utf-8",
    )
    trust = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {
                "Federated": (
                    "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                )
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/payments:*"},
            },
        },
    }
    plan = root / "plan.json"
    plan.write_text(
        json.dumps(
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_iam_role.deployer",
                                "type": "aws_iam_role",
                                "values": {
                                    "arn": "arn:aws:iam::123456789012:role/deployer",
                                    "assume_role_policy": json.dumps(trust),
                                },
                            },
                            {
                                "address": "aws_eks_access_entry.deployer",
                                "type": "aws_eks_access_entry",
                                "values": {
                                    "cluster_name": "production",
                                    "principal_arn": ("arn:aws:iam::123456789012:role/deployer"),
                                    "kubernetes_groups": ["eks-deployers"],
                                },
                            },
                        ]
                    }
                },
                "resource_changes": [],
            }
        ),
        encoding="utf-8",
    )
    rbac = root / "rbac.yaml"
    rbac.write_text(
        f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployer
  namespace: payments
rules:
  - apiGroups: [apps]
    resources: [deployments]
    verbs: [{", ".join(verbs)}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deployers
  namespace: payments
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: deployer
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: eks-deployers
""",
        encoding="utf-8",
    )
    return plan, rbac


def test_analyze_reports_only_newly_reachable_capability(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before_plan, before_rbac = write_revision(before, verbs=["get"])
    after_plan, after_rbac = write_revision(after, verbs=["get", "patch"])
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "analyze",
            "--repository",
            "acme/payments",
            "--before-oidc-subject-prefix",
            "repo:acme/payments",
            "--after-oidc-subject-prefix",
            "repo:acme/payments",
            "--before-root",
            str(before),
            "--before-plan",
            str(before_plan),
            "--before-rbac",
            str(before_rbac),
            "--after-root",
            str(after),
            "--after-plan",
            str(after_plan),
            "--after-rbac",
            str(after_rbac),
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["analysis_status"] == "proven_within_supported_static_inputs"
    assert len(report["newly_reachable"]) == 1
    assert report["newly_reachable"][0]["verb"] == "patch"
    assert len(report["newly_reachable"][0]["edge_sequence"]) == 5
    assert len(report["before_input_sha256"]) == 64
    assert len(report["after_input_sha256"]) == 64


def test_analyze_output_is_byte_stable(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before_plan, before_rbac = write_revision(before, verbs=["get"])
    after_plan, after_rbac = write_revision(after, verbs=["get", "patch"])
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    common = [
        "analyze",
        "--repository",
        "acme/payments",
        "--before-oidc-subject-prefix",
        "repo:acme/payments",
        "--after-oidc-subject-prefix",
        "repo:acme/payments",
        "--before-root",
        str(before),
        "--before-plan",
        str(before_plan),
        "--before-rbac",
        str(before_rbac),
        "--after-root",
        str(after),
        "--after-plan",
        str(after_plan),
        "--after-rbac",
        str(after_rbac),
    ]

    assert main([*common, "--output", str(first)]) == 0
    assert main([*common, "--output", str(second)]) == 0

    assert first.read_bytes() == second.read_bytes()


def test_analyze_can_render_deterministic_markdown(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    before_plan, before_rbac = write_revision(before, verbs=["get"])
    after_plan, after_rbac = write_revision(after, verbs=["get", "patch"])
    output = tmp_path / "report.md"

    assert (
        main(
            [
                "analyze",
                "--repository",
                "acme/payments",
                "--before-oidc-subject-prefix",
                "repo:acme/payments",
                "--after-oidc-subject-prefix",
                "repo:acme/payments",
                "--before-root",
                str(before),
                "--before-plan",
                str(before_plan),
                "--before-rbac",
                str(before_rbac),
                "--after-root",
                str(after),
                "--after-plan",
                str(after_plan),
                "--after-rbac",
                str(after_rbac),
                "--format",
                "markdown",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    rendered = output.read_text(encoding="utf-8")
    assert "## Findings" in rendered
    assert "## Diagnostics" in rendered
    assert "## Limitations" in rendered
    assert "patch" in rendered
