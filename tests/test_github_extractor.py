from pathlib import Path

import pytest

from authz_delta.extractors.github import extract_workflow
from authz_delta.model import ResultState


def write_workflow(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "deploy.yml"
    path.write_text(source, encoding="utf-8")
    return path


def test_extracts_literal_oidc_role_request(tmp_path: Path) -> None:
    path = write_workflow(
        tmp_path,
        """
name: deploy
on:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  production:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deployer
          aws-region: us-east-1
""",
    )

    result = extract_workflow(path, display_path=".github/workflows/deploy.yml")

    assert result.diagnostics == ()
    assert len(result.role_requests) == 1
    request = result.role_requests[0]
    assert request.workflow == ".github/workflows/deploy.yml"
    assert request.job == "production"
    assert request.role_arn == "arn:aws:iam::123456789012:role/deployer"
    assert request.events == ("push",)
    assert request.environment == "production"
    assert request.evidence[0].line == 14


def test_job_permissions_override_workflow_permissions(tmp_path: Path) -> None:
    path = write_workflow(
        tmp_path,
        """
on: push
permissions:
  id-token: write
jobs:
  deploy:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deployer
""",
    )

    result = extract_workflow(path)

    assert result.role_requests == ()
    assert {item.code for item in result.diagnostics} == {"github_id_token_not_enabled"}
    assert result.diagnostics[0].state is ResultState.NOT_EVALUATED


def test_expression_role_is_indeterminate(tmp_path: Path) -> None:
    path = write_workflow(
        tmp_path,
        """
on: workflow_dispatch
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.DEPLOY_ROLE }}
""",
    )

    result = extract_workflow(path)

    assert result.role_requests == ()
    assert {item.code for item in result.diagnostics} == {"github_expression_unsupported"}
    assert result.diagnostics[0].state is ResultState.INDETERMINATE


def test_duplicate_yaml_key_is_an_input_error(tmp_path: Path) -> None:
    path = write_workflow(
        tmp_path,
        """
on: push
on: pull_request
jobs: {}
""",
    )

    result = extract_workflow(path)

    assert result.role_requests == ()
    assert {item.code for item in result.diagnostics} == {"yaml_duplicate_key"}
    assert result.diagnostics[0].state is ResultState.INDETERMINATE


def test_local_composite_action_is_explicitly_unsupported(tmp_path: Path) -> None:
    path = write_workflow(
        tmp_path,
        """
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/deploy
""",
    )

    result = extract_workflow(path)

    assert result.role_requests == ()
    assert {item.code for item in result.diagnostics} == {"github_composite_action_unsupported"}


@pytest.mark.parametrize(
    ("job_fragment", "expected_code"),
    [
        (
            "uses: owner/repository/.github/workflows/deploy.yml@main",
            "github_reusable_workflow_unsupported",
        ),
        (
            "strategy:\n      matrix:\n        region: [us-east-1]\n    runs-on: ubuntu-latest",
            "github_matrix_unsupported",
        ),
    ],
)
def test_unsupported_job_features_are_explicit(
    tmp_path: Path, job_fragment: str, expected_code: str
) -> None:
    path = write_workflow(
        tmp_path,
        f"""
on: push
permissions:
  id-token: write
jobs:
  deploy:
    {job_fragment}
""",
    )

    result = extract_workflow(path)

    assert result.role_requests == ()
    assert {item.code for item in result.diagnostics} == {expected_code}
