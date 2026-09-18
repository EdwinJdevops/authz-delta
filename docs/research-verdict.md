# Research verdict

## Decision

Build a bounded open-source analyzer. Do **not** build a universal cloud-permission engine, automated remediation service, or AI security platform.

The problem is specific: a code review can change multiple declarative objects that together broaden which GitHub Actions identity can reach which Kubernetes API capability. A reviewer normally has to join the trust policy, the EKS identity mapping, the Kubernetes group, the binding, and the role rule mentally. The proposed analyzer computes that join for a strictly defined static subset.

## Verified technical basis

GitHub says a workflow needs `id-token: write` to request an OIDC token. It recommends a condition on GitHub's `sub` claim in an AWS trust policy, and documents that a broad `StringLike` condition can allow any branch, pull-request merge branch, or environment in a repository. AWS EKS access entries associate an IAM principal with either EKS access policies or Kubernetes groups. Kubernetes bindings attach roles to users, groups, or service accounts; a ClusterRoleBinding can make cluster-wide role rules reachable by a group.^1 ^2 ^3 ^4

This is enough to justify a static graph for the supported path. It is not enough to claim complete AWS effective permissions.

## The problem, stated precisely

Given two repository revisions containing:

- GitHub Actions workflows;
- declarative AWS IAM role trust configuration;
- declarative EKS access-entry configuration; and
- Kubernetes RBAC manifests,

identify every new statically provable tuple:

`GitHub OIDC subject pattern → IAM role → EKS cluster → Kubernetes group → scope → API group → resource → verb`

and show the exact files and objects that created each new tuple.

The result is a **review aid**. It says: “under the explicitly supported model, this source identity now reaches these Kubernetes capabilities.” It does not say the role can perform every AWS API action, that the workflow will run, or that the live cluster is configured exactly as the repository declares.

## Essential correction: two identity paths, not one

The original broad phrasing mixed two distinct paths:

| Path | What it does | Release-0 treatment |
|---|---|---|
| GitHub OIDC → AWS role → EKS API authentication → Kubernetes RBAC | A CI job gets temporary AWS credentials and uses an IAM principal to authenticate to an EKS cluster. | **In scope**, only when represented with EKS access entries and Kubernetes groups. |
| Kubernetes service account → IRSA or EKS Pod Identity → AWS role | A Pod gets AWS credentials through its service account. AWS documents this separately from GitHub OIDC. | **Out of scope.** |

IRSA also has an important limitation: AWS explicitly warns that containers are not a security boundary and that IMDS configuration can expose node-role credentials. EKS Pod Identity is another distinct association mechanism. Combining either with the GitHub chain would make the analysis unsound.^5 ^6

## What existing tools cover

| Tool or mechanism | Verified coverage | Why AuthZ Delta is not a replacement |
|---|---|---|
| IAM Access Analyzer | Policy grammar/best-practice validation, external/internal/unused access analysis, and custom policy checks for new access. | It is AWS IAM-focused. The cited AWS documentation does not describe a repository-level GitHub-OIDC-to-EKS-RBAC delta graph. |
| IAM policy simulator | Evaluates supplied or attached IAM policies for selected API actions/resources. | AWS says results can differ from the live environment; it does not automatically fetch resource policies, and resource-policy simulation is not supported for IAM roles. |
| EKS access entries | AWS-managed mapping from IAM principals to Kubernetes access policies or groups. | It provides the mapping layer, not a before/after review graph across GitHub workflows and RBAC manifests. |
| Kubernetes RBAC | Binds users/groups/service accounts to role rules. | It provides the authorization mechanism, not identity provenance from GitHub or IAM trust policies. |
| CI static analyzers, including zizmor and Checkov | Analyze GitHub Actions configuration and IaC policy patterns respectively. | They are complementary. They do not eliminate the need to explain a composed cross-file reachability change. |

This is not proof of market whitespace. I cannot verify that no commercial product or private internal tool has implemented this exact analysis. The claim is narrower: the supported documents above do not themselves provide it as a single open-source repository-delta analyzer.

## Hard technical limits

AWS authorization is request-context dependent. AWS documents union and intersection behavior across identity policies, resource policies, permissions boundaries, SCPs, and RCPs; explicit denies override allows. The IAM simulator also requires context values and warns that its results may differ from live AWS. A repository-only analyzer cannot truthfully compute all effective AWS permissions.^7 ^8

Kubernetes is also not a closed static language. ClusterRole aggregation can add rules to `admin`, `edit`, and `view`; default roles can be auto-reconciled; `aws-auth` is deprecated but still present on older clusters; EKS access policies are AWS-maintained; admission controllers and custom authorizers can affect actual access. These are reasons to exclude unsupported mechanisms rather than hand-wave around them.^3 ^4 ^9

## Product judgment

**Worth building as an engineering and open-source research project: yes.** It has a defensible, testable core and directly demonstrates identity, IAM, EKS, Kubernetes, Terraform, secure CI, graph modelling, and disciplined scope control.

**Worth claiming as a venture company or global category leader today: no.** There is no customer evidence, no validated distribution, no production corpus, and no proof that a single static analyzer is a budget-holding pain point. Do not make acquisition, investor, “AI security platform,” or “prevents breaches” claims.

The first success criterion is not followers, a dashboard, or an AWS deployment. It is a small test corpus where a reviewer can see a dangerous authorization expansion that ordinary per-file review obscures, and where the tool reports it deterministically with honest limitations.

## Release-0 scope

| Include | Exclude |
|---|---|
| GitHub OIDC `sub` and `aud` trust-policy conditions | GitHub reusable workflows, composite actions, live GitHub settings, untrusted-event taint analysis |
| IAM role trust relation only | IAM effective permission calculation, SCP/RCP/boundary/session/resource policies |
| EKS access entries using `kubernetes_groups` | EKS access-policy associations and legacy `aws-auth` |
| Direct Roles/ClusterRoles and bindings | aggregated roles, CRDs, admission, external authorizers |
| Terraform/OpenTofu JSON plan + Kubernetes YAML snapshots | executing Terraform, contacting AWS, applying YAML |

## Evidence and falsification plan

The project should be abandoned or narrowed further if any of these occur:

1. A realistic fixture cannot be made without adding more than one excluded mechanism.
2. The graph output merely restates direct `cluster-admin` assignments and does not surface a composed delta.
3. The tool cannot distinguish a widened OIDC subject pattern from an unchanged one.
4. Output is nondeterministic or hides unsupported inputs.
5. Independent reviewers find its model confusing or misleading.

The project earns its next phase only after a fixture suite covers: new subject pattern, changed EKS group mapping, changed RoleBinding, changed ClusterRole rule, a no-op diff, malformed input, and each explicit non-goal.

## Sources

1. GitHub. [Configuring OpenID Connect in Amazon Web Services](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws). Accessed 11 September 2026.
2. AWS. [Grant IAM users access to Kubernetes with EKS access entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html). Accessed 11 September 2026.
3. Kubernetes. [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/). Accessed 11 September 2026.
4. AWS. [Grant IAM users access to Kubernetes with a ConfigMap](https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html). Accessed 11 September 2026.
5. AWS. [IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html). Accessed 11 September 2026.
6. AWS. [EKS Pod Identities](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html). Accessed 11 September 2026.
7. AWS. [Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html). Accessed 11 September 2026.
8. AWS. [SimulatePrincipalPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html). Accessed 11 September 2026.
9. AWS. [Using IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html). Accessed 11 September 2026.
10. zizmor. [Documentation](https://docs.zizmor.sh/). Accessed 11 September 2026.
