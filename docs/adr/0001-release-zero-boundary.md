# ADR 0001: Release-0 boundary

## Status

Accepted.

## Context

The project needs a verifiable technical claim. AWS IAM, GitHub OIDC, EKS authentication, and Kubernetes RBAC have distinct evaluation semantics. A broad claim about effective cloud permissions cannot be supported with repository data alone.

## Decision

Analyze only GitHub OIDC trust patterns, EKS access entries with Kubernetes groups, and direct non-aggregated Kubernetes RBAC resources. Produce potential, statically evidenced Kubernetes API capability deltas.

Do not evaluate `aws-auth`, EKS access policies, IRSA, Pod Identity, IAM permission policies, organization controls, or runtime state.

## Consequences

The first release will miss real paths and must emit limitations. In return, its result is explainable, testable, credential-free, and honest about what it knows.
