"""Normalized facts and diagnostics used by the trusted analysis core."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
from typing import Any


class ResultState(str, Enum):
    """Truth states exposed by the analyzer."""

    PROVEN = "proven"
    INDETERMINATE = "indeterminate"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, order=True)
class SourceLocation:
    """Stable location of an input fact."""

    file: str
    document: int = 0
    path: str = ""
    line: int | None = None

    @classmethod
    def from_mapping(cls, value: object) -> SourceLocation:
        if not isinstance(value, dict):
            raise ValueError("source location must be a JSON object")
        allowed = {"file", "document", "path", "line"}
        unexpected = sorted(set(value).difference(allowed))
        if unexpected:
            raise ValueError(f"unexpected source location fields: {', '.join(unexpected)}")
        file = value.get("file")
        document = value.get("document", 0)
        path = value.get("path", "")
        line = value.get("line")
        if not isinstance(file, str) or not file:
            raise ValueError("source location file must be a non-empty string")
        if not isinstance(document, int) or document < 0:
            raise ValueError("source location document must be a non-negative integer")
        if not isinstance(path, str):
            raise ValueError("source location path must be a string")
        if line is not None and (not isinstance(line, int) or line < 1):
            raise ValueError("source location line must be a positive integer")
        return cls(file=file, document=document, path=path, line=line)

    def to_mapping(self) -> dict[str, object]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True, order=True)
class Capability:
    """A statically evidenced GitHub OIDC-to-Kubernetes capability path."""

    workflow: str
    job: str
    oidc_subject: str
    role_arn: str
    cluster: str
    kubernetes_group: str
    scope: str
    api_group: str
    resource: str
    verb: str
    evidence: tuple[SourceLocation, ...]

    @classmethod
    def from_mapping(cls, value: object) -> Capability:
        """Create a capability from a validated JSON object."""
        if not isinstance(value, dict):
            raise ValueError("capability must be a JSON object")

        required = (
            "workflow",
            "job",
            "oidc_subject",
            "role_arn",
            "cluster",
            "kubernetes_group",
            "scope",
            "api_group",
            "resource",
            "verb",
            "evidence",
        )
        missing = [field for field in required if field not in value]
        if missing:
            raise ValueError(f"capability is missing required fields: {', '.join(missing)}")

        evidence = value["evidence"]
        if not isinstance(evidence, list):
            raise ValueError("capability evidence must be an array")

        values = {field: value[field] for field in required if field != "evidence"}
        if not all(isinstance(item, str) for item in values.values()):
            raise ValueError("capability identity fields must be strings")
        required_non_empty = {field: item for field, item in values.items() if field != "api_group"}
        if not all(required_non_empty.values()):
            raise ValueError("capability identity fields other than api_group must be non-empty")

        return cls(
            **values,
            evidence=tuple(sorted(SourceLocation.from_mapping(item) for item in evidence)),
        )

    @property
    def identity(self) -> tuple[str, ...]:
        """Return the semantic identity, excluding source evidence."""
        return (
            self.workflow,
            self.job,
            self.oidc_subject,
            self.role_arn,
            self.cluster,
            self.kubernetes_group,
            self.scope,
            self.api_group,
            self.resource,
            self.verb,
        )

    @property
    def anchors(self) -> frozenset[str]:
        return frozenset(item for item in self.identity if item)

    @property
    def finding_id(self) -> str:
        canonical = "\x1f".join(self.identity).encode()
        return f"AZD-{sha256(canonical).hexdigest()[:16]}"

    def to_mapping(self) -> dict[str, object]:
        """Return a JSON-serializable representation with stable ordering."""
        result: dict[str, Any] = asdict(self)
        result["finding_id"] = self.finding_id
        result["state"] = ResultState.PROVEN.value
        result["evidence"] = [item.to_mapping() for item in self.evidence]
        result["edge_sequence"] = [
            {
                "from": f"github_job:{self.workflow}#{self.job}",
                "relation": "emits_oidc_subject",
                "to": self.oidc_subject,
            },
            {
                "from": self.oidc_subject,
                "relation": "trusted_to_assume",
                "to": self.role_arn,
            },
            {
                "from": self.role_arn,
                "relation": "mapped_by_eks_access_entry",
                "to": f"{self.cluster}#{self.kubernetes_group}",
            },
            {
                "from": self.kubernetes_group,
                "relation": "bound_in_scope",
                "to": self.scope,
            },
            {
                "from": self.scope,
                "relation": "grants",
                "to": f"{self.api_group}/{self.resource}:{self.verb}",
            },
        ]
        return result


@dataclass(frozen=True, order=True)
class Diagnostic:
    """An explicit boundary, malformed input, or unresolved semantic."""

    code: str
    state: ResultState
    message: str
    anchors: tuple[str, ...] = ()
    evidence: tuple[SourceLocation, ...] = ()

    @classmethod
    def from_mapping(cls, value: object) -> Diagnostic:
        if not isinstance(value, dict):
            raise ValueError("diagnostic must be a JSON object")
        required = {"code", "state", "message"}
        missing = sorted(required.difference(value))
        if missing:
            raise ValueError(f"diagnostic is missing required fields: {', '.join(missing)}")
        code = value["code"]
        message = value["message"]
        anchors = value.get("anchors", [])
        evidence = value.get("evidence", [])
        if not isinstance(code, str) or not code:
            raise ValueError("diagnostic code must be a non-empty string")
        if not isinstance(message, str) or not message:
            raise ValueError("diagnostic message must be a non-empty string")
        if not isinstance(anchors, list) or not all(isinstance(item, str) for item in anchors):
            raise ValueError("diagnostic anchors must be an array of strings")
        if not isinstance(evidence, list):
            raise ValueError("diagnostic evidence must be an array")
        try:
            state = ResultState(value["state"])
        except (TypeError, ValueError) as error:
            raise ValueError("diagnostic state is invalid") from error
        if state is ResultState.PROVEN:
            raise ValueError("diagnostics cannot use the proven state")
        return cls(
            code=code,
            state=state,
            message=message,
            anchors=tuple(sorted(set(anchors))),
            evidence=tuple(sorted(SourceLocation.from_mapping(item) for item in evidence)),
        )

    def affects(self, capability: Capability) -> bool:
        """Return whether this uncertainty can affect a capability comparison."""
        return not self.anchors or not capability.anchors.isdisjoint(self.anchors)

    def to_mapping(self) -> dict[str, object]:
        return {
            "code": self.code,
            "state": self.state.value,
            "message": self.message,
            "anchors": list(self.anchors),
            "evidence": [item.to_mapping() for item in self.evidence],
        }


@dataclass(frozen=True)
class Snapshot:
    """Normalized facts for one immutable repository revision."""

    capabilities: frozenset[Capability]
    diagnostics: tuple[Diagnostic, ...] = ()

    @classmethod
    def from_mapping(cls, value: object) -> Snapshot:
        if not isinstance(value, dict):
            raise ValueError("snapshot must be a JSON object")
        allowed = {"schema_version", "capabilities", "diagnostics"}
        unexpected = sorted(set(value).difference(allowed))
        if unexpected:
            raise ValueError(f"unexpected snapshot fields: {', '.join(unexpected)}")
        if value.get("schema_version") != "0.2":
            raise ValueError("snapshot schema_version must be '0.2'")
        capabilities = value.get("capabilities")
        diagnostics = value.get("diagnostics", [])
        if not isinstance(capabilities, list):
            raise ValueError("snapshot capabilities must be an array")
        if not isinstance(diagnostics, list):
            raise ValueError("snapshot diagnostics must be an array")
        return cls(
            capabilities=frozenset(Capability.from_mapping(item) for item in capabilities),
            diagnostics=tuple(sorted(Diagnostic.from_mapping(item) for item in diagnostics)),
        )
