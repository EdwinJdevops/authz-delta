# AGENTS.md — AuthZ Delta

## Mission

Build a deterministic, offline analyzer that compares two repository revisions and reports **newly reachable Kubernetes API capabilities** introduced through this supported path:

`GitHub Actions OIDC subject → AWS IAM role trust → EKS access entry → Kubernetes group → RoleBinding / ClusterRoleBinding → Role / ClusterRole rule`

The tool is an evidence generator. It must never claim that a change is safe, that it has calculated all AWS effective permissions, or that a result represents runtime authorization unless every required input is present and supported.

## Release-0 boundary (mandatory)

Supported inputs:

- GitHub Actions workflow YAML in `.github/workflows/`.
- Terraform/OpenTofu JSON plan output containing AWS IAM role trust policies and EKS access entries.
- Kubernetes YAML containing `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding`.
- GitHub OIDC provider `token.actions.githubusercontent.com` only.
- EKS access entries with `kubernetes_groups` only.

Unsupported and therefore must be reported as `unknown`, never guessed:

- Legacy `aws-auth` ConfigMap.
- EKS access-policy associations.
- IRSA, EKS Pod Identity, node-role credentials, or `hostNetwork`/IMDS effects.
- AWS Organizations SCPs/RCPs, permission boundaries, session policies, resource-based policies, live AWS state, and dynamic IAM condition evaluation.
- Reusable-workflow call graph, composite actions, generated manifests, Helm rendering, Kustomize overlays, CRDs, Kubernetes admission controllers, and aggregated ClusterRoles.

Do not silently expand the supported boundary.

## Required architecture

Use Python 3.10 or newer. Keep the core library pure and side-effect free.

```text
CLI
 ├── repository loader
 ├── revision snapshot builder
 │    ├── GitHub workflow extractor
 │    ├── Terraform plan extractor
 │    └── Kubernetes RBAC extractor
 ├── normalized fact graph
 ├── reachability evaluator
 ├── delta engine
 └── JSON + Markdown renderers
```

No database, web service, AWS credentials, GitHub token, LLM, or Kubernetes cluster is permitted in Release 0.

## Truth model

Every result must carry one of these states:

- `proven`: all edges in the result are represented by supported static inputs.
- `indeterminate`: a relevant unknown or unsupported mechanism could change the result.
- `not_evaluated`: deliberately outside the requested analysis.

Never use `safe`, `secure`, `effective_permissions`, or `production-ready` as a status.

A capability is `newly_reachable` only when its complete after-path is `proven`, no
equivalent complete before-path is `proven`, and no relevant `indeterminate` or
`not_evaluated` diagnostic in either revision could affect the source identity, IAM role,
cluster, Kubernetes group, scope, resource, or verb. Otherwise emit an
`indeterminate_delta` diagnostic, not a finding.

Terraform/OpenTofu values are supported only when represented as concrete values in the
JSON plan. Unknown, computed, absent, or sensitive-without-concrete values remain
indeterminate. Never evaluate an expression or synthesize an ARN.

GitHub workflow extraction supports literal YAML scalar values only: mapping-form
permissions, literal `id-token: write`, literal workflow events, literal
`aws-actions/configure-aws-credentials` references, and literal `role-to-assume` values.
Expressions, reusable workflows, composite actions, matrices, shorthand permissions,
environment-derived values, inputs, outputs, secrets, variables, and shell-derived values
are indeterminate.

Each finding must include:

- stable finding ID;
- source and target revision hashes;
- source file paths and object identifiers;
- the full edge sequence;
- newly reachable `(cluster, scope, apiGroup, resource, verb)` tuple;
- status and limitations.

## Engineering rules

- Parse untrusted YAML and JSON without executing templates, shell, Terraform, or actions.
- Reject duplicate YAML keys or report them as input errors.
- Preserve source locations where parsers expose them.
- Sort all collections before rendering. Identical inputs must produce byte-stable JSON.
- Write no credentials to logs, fixtures, output, Git history, or test snapshots.
- Treat malformed input as an explicit diagnostic, not an empty result.
- Add a regression fixture for every bug.
- Do not introduce an LLM into authorization evaluation. An LLM may later explain a completed report, outside the trusted core.

## Testing gates

Before any change is considered complete, run:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

Required test classes:

- unit tests for every extractor and graph rule;
- adversarial fixtures for widened GitHub OIDC `sub` patterns;
- tests proving no finding when an IAM role is not mapped to an EKS access entry;
- tests proving changed Kubernetes bindings/rules create a delta;
- determinism test for JSON output;
- boundary tests that emit `unknown` for each unsupported feature.

## Change discipline

Before editing, read `README.md`, `docs/architecture.md`, and the relevant ADR.

For every non-trivial change:

1. State the supported semantic being added.
2. Add a failing fixture and test.
3. Implement the smallest change that makes it pass.
4. Run the full test gate.
5. Update the scope/limitations documentation if the boundary changed.

Never add a feature because it sounds comprehensive. Add it only when its semantics and tests are defined.
