# AuthZ Delta

AuthZ Delta compares two declarative infrastructure snapshots and reports newly reachable Kubernetes API capabilities on a supported CI-to-EKS authorization path.

## What problem it solves

An authorization expansion can be distributed across a GitHub Actions workflow, an IAM role trust policy, an EKS identity mapping, and Kubernetes RBAC. Reviewers often see these as separate files. The result is that a change can broaden who may reach a Kubernetes capability without a single obvious `cluster-admin` line.

The tool makes this specific static change visible.

## Initial supported path

`GitHub OIDC subject → IAM role → EKS access entry groups → Kubernetes RBAC → Kubernetes API capability`

The initial release is deliberately not an AWS permission simulator and not a runtime authorization engine. See [architecture](docs/architecture.md) and [scope decision](docs/research-verdict.md).

## Status

Design and fixture phase. Do not use for access-control decisions.
