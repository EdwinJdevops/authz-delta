# Codex CLI build runbook

## Operating rule

Use Codex for bounded tasks, not one instruction asking it to “build the whole product.” Every task below has an acceptance condition. Read and review the diff before committing. Do not grant it cloud credentials for Release 0 because the analyzer must work offline.

## 0. Prepare the working directory

Run these commands after opening Ubuntu:

```bash
mkdir -p ~/src
cd ~/src
mkdir authz-delta
cd authz-delta
git init
git branch -M main
python3 --version
git --version
codex --version
```

The supported starter uses Python 3.10 or newer. If `python3 --version` is lower than 3.10, stop here and install a supported Python version through your Ubuntu-supported package source before continuing. Do not work around it by changing the project’s declared version.

Copy this repository’s `AGENTS.md`, `pyproject.toml`, `src/`, `tests/`, `fixtures/`, and `docs/` into this directory. Then create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m ruff check .
python -m ruff format --check .
python -m mypy src
python -m pytest -q
git add .
git commit -m "chore: establish deterministic delta core"
```

Expected initial result: lint passes, typing passes, and two tests pass. The CLI can compare normalized JSON facts only. That is intentional; it is the tested kernel, not the claimed product.

## 1. Freeze the input schema before writing extractors

Start Codex from the repository root:

```bash
codex
```

Paste exactly:

```text
Read AGENTS.md, README.md, docs/architecture.md, docs/research-verdict.md, and docs/adr/0001-release-zero-boundary.md. Do not write code yet. Create docs/adr/0002-normalized-fact-schema.md and docs/schemas/snapshot.schema.json. Define a versioned JSON schema for the normalized capability facts and diagnostics. The schema must represent source locations, edge evidence, `proven`/`unknown`/`not_evaluated`, and input hashes. Keep the Release-0 exclusions unchanged. Add a test that validates the existing normalized fixtures against the schema. Use a maintained Python JSON Schema library only if you add it explicitly to pyproject.toml. Run the full test gate and report changed files and results.
```

Accept only if it adds the schema, validates both fixtures, and does not introduce any AWS/GitHub network client.

Commit:

```bash
git add . && git commit -m "docs: define normalized fact schema"
```

## 2. Build the adversarial corpus first

Paste:

```text
Read AGENTS.md and the accepted schema ADR. Create a fixture corpus for two complete revisions of a minimal GitHub OIDC to EKS access-entry to Kubernetes RBAC path. Add paired cases for: a widened GitHub `sub` condition, a new EKS Kubernetes group mapping, a new RoleBinding, a new ClusterRole rule, a no-op revision, malformed YAML/JSON, legacy aws-auth, aggregated ClusterRole, IRSA annotation, and EKS Pod Identity association. For excluded inputs, define expected `unknown` or `not_evaluated` diagnostics; do not fake a capability. Write tests against the expected normalized facts and diagnostics. Do not implement extractors yet. Run the full test gate.
```

Accept only if each fixture has an explicit expected outcome and the corpus contains no real account IDs, credentials, tokens, or copied production manifests.

## 3. Implement GitHub OIDC extraction

Paste:

```text
Implement only the GitHub Actions extractor required by AGENTS.md. Parse workflow YAML without executing anything. Extract job-level and workflow-level `permissions`, the presence of `id-token: write`, event names, and the role ARN passed to aws-actions/configure-aws-credentials only when that action reference and input are statically literal. Do not resolve expressions, reusable workflows, composite actions, or third-party actions. Emit an explicit diagnostic for each unsupported form. Add fixtures for `id-token: write` inherited at workflow and job level, missing token permission, literal role ARN, and dynamic expression. Preserve file paths. Run the full test gate.
```

Accept only if the extractor never infers a subject pattern from the workflow. Subject patterns belong to the IAM trust policy.

## 4. Implement Terraform/OpenTofu plan extraction for IAM trust and EKS access entries

Paste:

```text
Implement a read-only extractor for Terraform/OpenTofu JSON plan output. Support only aws_iam_role assume_role_policy documents for GitHub's token.actions.githubusercontent.com OIDC provider and aws_eks_access_entry values that contain kubernetes_groups. Extract role ARN only when account ID and role name are known values. Parse StringEquals and StringLike conditions for the GitHub `aud` and `sub` condition keys. Emit `unknown` when a relevant Terraform value is unknown, the provider differs, a condition operator is unsupported, an access-policy association is present, or the plan lacks required values. Do not evaluate IAM permission policies. Add fixtures and tests for each condition. Run the full test gate.
```

Accept only if wildcard subject patterns are retained exactly, never converted into a narrower value.

## 5. Implement Kubernetes RBAC extraction

Paste:

```text
Implement only the Kubernetes RBAC extractor described in AGENTS.md. Support rbac.authorization.k8s.io/v1 Role, ClusterRole, RoleBinding, and ClusterRoleBinding objects. Resolve direct roleRef references and group subjects. Emit normalized capability rules for literal apiGroups, resources, and verbs. Treat an empty apiGroup as valid for the Kubernetes core API. Emit `not_evaluated` for aggregationRule, unknown role references, non-group subjects, wildcard rules, and non-RBAC objects that could affect authorization. Do not execute Helm, Kustomize, templates, or admission policies. Add unit and corpus tests. Run the full test gate.
```

Accept only if a ClusterRoleBinding is shown as cluster-scoped and a RoleBinding as namespace-scoped.

## 6. Join the graph and compute a revision delta

Paste:

```text
Implement the graph join for the exact Release-0 path: GitHub OIDC sub pattern -> IAM role trust -> EKS access entry Kubernetes groups -> direct Kubernetes group bindings -> direct role rules. Join only exact role ARNs and exact group strings. Output each complete edge sequence and source location. Preserve an explicit status for unsupported inputs. Do not add AWS IAM permission edges or service-account-to-AWS identity paths. Add an end-to-end fixture proving that an OIDC sub widening, an EKS group addition, and a Kubernetes RBAC change independently create different new capability deltas. Run the full test gate.
```

Accept only if the finding can name every connecting object. A partial path must be a diagnostic, not a finding.

## 7. Make output reviewable and stable

Paste:

```text
Add a versioned JSON evidence report and a Markdown renderer. Each finding must include a stable ID, before and after input hashes, complete path, source locations, newly reachable capability tuple, and status. The Markdown report must have separate Findings, Diagnostics, and Limitations sections. Add snapshot tests proving byte-stable JSON and deterministic finding order. Do not add a web UI, database, cloud service, LLM, GitHub App, or automatic PR comments. Run the full test gate.
```

## 8. Harden the parser boundary

Paste:

```text
Perform a security review of the local parsers. Add size limits, maximum document limits, duplicate-key rejection, clear parser errors, path traversal protection, and tests for hostile-but-non-executing YAML/JSON inputs. Confirm that no input is shell-executed, templated, or fetched from the network. Document every limit in docs/security.md. Run the full test gate.
```

## 9. Manual review before a GitHub Action

Do not add a GitHub Action until the local corpus and JSON report are correct. First run:

```bash
git diff main...HEAD
python -m pytest -q
```

Then ask Codex:

```text
Review this repository against AGENTS.md as a hostile security reviewer. Do not change files. Identify unsound inferences, scope violations, missing negative tests, nondeterminism, parser risks, and claims unsupported by docs/research-verdict.md. Rank findings by severity and cite exact files.
```

Fix each valid finding in a separate commit.

## 10. First integration, only after local correctness

The first integration should be a GitHub Action that runs the local CLI against checked-in fixtures or a pull-request diff and uploads the JSON report as an artifact. It must have the smallest possible `GITHUB_TOKEN` permissions and must not request `id-token: write`, AWS credentials, or cluster credentials. Those are unnecessary for a local analyzer.

Before writing it, create an ADR that specifies the pull-request snapshot acquisition method and threat model. Do not let the Action run untrusted repository code.

## Article sequence

Write only after each corresponding artifact exists and is tested:

1. **The review problem:** show the separate identity layers and their source documents.
2. **Why this is not an IAM simulator:** document AWS evaluation limits and project boundary.
3. **Building the corpus:** publish sanitized fixtures and expected deltas.
4. **The graph join:** explain each typed edge and deterministic report.
5. **What the analyzer refuses to claim:** publish the limitations and future research boundary.
