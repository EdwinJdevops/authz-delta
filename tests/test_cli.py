import json
from pathlib import Path

from authz_delta.cli import main


def test_compare_writes_deterministic_json_report(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    output = tmp_path / "report.json"
    before.write_text(
        '{"schema_version": "0.2", "capabilities": [], "diagnostics": []}\n',
        encoding="utf-8",
    )
    after.write_text(
        json.dumps(
            {
                "schema_version": "0.2",
                "capabilities": [
                    {
                        "workflow": "deploy.yml",
                        "job": "deploy",
                        "oidc_subject": "repo:acme/platform:environment:production",
                        "role_arn": "arn:aws:iam::123456789012:role/deployer",
                        "cluster": "arn:aws:eks:us-east-1:123456789012:cluster/platform",
                        "kubernetes_group": "platform-deployers",
                        "scope": "cluster",
                        "api_group": "",
                        "resource": "secrets",
                        "verb": "get",
                        "evidence": [
                            {"file": "binding.yaml", "path": "subjects[0]"},
                            {"file": "role.yaml", "path": "rules[0]"},
                        ],
                    }
                ],
                "diagnostics": [],
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "compare",
                "--before",
                str(before),
                "--after",
                str(after),
                "--output",
                str(output),
            ]
        )
        == 0
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["analysis_status"] == "proven_for_normalized_snapshot_only"
    assert report["newly_reachable"][0]["resource"] == "secrets"
    assert report["newly_reachable"][0]["finding_id"].startswith("AZD-")
