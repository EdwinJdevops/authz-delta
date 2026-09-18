from pathlib import Path

from authz_delta.extractors.kubernetes import extract_rbac
from authz_delta.model import ResultState


def write_manifests(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "rbac.yaml"
    path.write_text(source, encoding="utf-8")
    return path


def test_extracts_roles_rules_and_group_bindings(tmp_path: Path) -> None:
    path = write_manifests(
        tmp_path,
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployer
  namespace: payments
rules:
  - apiGroups: [apps]
    resources: [deployments]
    verbs: [get, patch]
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
  - kind: ServiceAccount
    name: ignored-for-this-path
""",
    )

    result = extract_rbac(path, display_path="k8s/rbac.yaml")

    assert result.diagnostics == ()
    assert len(result.roles) == 1
    role = result.roles[0]
    assert (role.kind, role.name, role.namespace) == ("Role", "deployer", "payments")
    assert role.rules[0].api_groups == ("apps",)
    assert role.rules[0].resources == ("deployments",)
    assert role.rules[0].verbs == ("get", "patch")
    assert len(result.bindings) == 1
    binding = result.bindings[0]
    assert binding.groups == ("eks-deployers",)
    assert binding.role_kind == "Role"
    assert binding.role_name == "deployer"


def test_aggregated_cluster_role_is_indeterminate(tmp_path: Path) -> None:
    path = write_manifests(
        tmp_path,
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: aggregate-reader
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        rbac.example.com/aggregate: "true"
rules: []
""",
    )

    result = extract_rbac(path)

    assert result.roles == ()
    assert {item.code for item in result.diagnostics} == {"rbac_aggregation_unsupported"}
    assert result.diagnostics[0].state is ResultState.INDETERMINATE


def test_namespaced_object_without_namespace_is_indeterminate(tmp_path: Path) -> None:
    path = write_manifests(
        tmp_path,
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployer
rules: []
""",
    )

    result = extract_rbac(path)

    assert result.roles == ()
    assert {item.code for item in result.diagnostics} == {"rbac_namespace_absent"}


def test_resource_names_rule_is_not_flattened(tmp_path: Path) -> None:
    path = write_manifests(
        tmp_path,
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: named-secret-reader
rules:
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [registry-token]
    verbs: [get]
""",
    )

    result = extract_rbac(path)

    assert result.roles == ()
    assert {item.code for item in result.diagnostics} == {"rbac_resource_names_unsupported"}


def test_duplicate_key_in_any_document_is_an_input_error(tmp_path: Path) -> None:
    path = write_manifests(
        tmp_path,
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
kind: Role
metadata:
  name: broken
""",
    )

    result = extract_rbac(path)

    assert result.roles == ()
    assert result.bindings == ()
    assert {item.code for item in result.diagnostics} == {"yaml_duplicate_key"}


def test_legacy_aws_auth_configmap_is_global_indeterminate_input(tmp_path: Path) -> None:
    path = write_manifests(
        tmp_path,
        """
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: arn:aws:iam::123456789012:role/deployer
      groups:
        - system:masters
""",
    )

    result = extract_rbac(path)

    assert result.roles == ()
    assert result.bindings == ()
    assert {item.code for item in result.diagnostics} == {"eks_aws_auth_unsupported"}
    assert result.diagnostics[0].anchors == ()
