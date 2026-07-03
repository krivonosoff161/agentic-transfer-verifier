"""Core transfer envelope models.

The models are intentionally small and dependency-free. They are a research
contract, not a universal standard.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

TrustLevel = Literal[
    "untrusted",
    "tool_observed",
    "user_confirmed",
    "verified",
    "signed",
    "attested",
]
AuthorityScope = Literal["none", "read", "write", "execute", "admin"]
ReportStatus = Literal["PASS", "WARN", "FAIL"]
RiskLevel = Literal["none", "low", "medium", "high"]
ConsumptionMode = Literal["data", "evidence", "memory", "instruction", "policy", "capability_grant"]


@dataclass(frozen=True)
class ProvenanceStep:
    actor: str
    action: str
    source: str
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IdentityClaim:
    subject: str
    issuer: str = ""
    credential_type: str = ""
    verified: bool = False
    binding: str = ""
    expires_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilityGrant:
    name: str
    scope: AuthorityScope
    source: str = ""
    bound_to: str = ""
    expires_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TransferEnvelope:
    envelope_id: str
    producer: str
    consumer: str
    payload_kind: str
    trust_level: TrustLevel
    authority_scope: AuthorityScope
    payload: dict[str, Any]
    provenance: list[ProvenanceStep] = field(default_factory=list)
    consumed_as: ConsumptionMode = "data"
    allowed_uses: list[str] = field(default_factory=list)
    identity_claims: list[IdentityClaim] = field(default_factory=list)
    capabilities: list[CapabilityGrant] = field(default_factory=list)
    created_at: str = ""
    expires_at: str = ""
    approval_id: str = ""
    approval_binding: str = ""
    parent_envelope_id: str = ""
    schema_version: str = "0.1"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["provenance"] = [step.to_dict() for step in self.provenance]
        data["identity_claims"] = [claim.to_dict() for claim in self.identity_claims]
        data["capabilities"] = [capability.to_dict() for capability in self.capabilities]
        return data


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Literal["low", "medium", "high"]
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VerificationReport:
    envelope_id: str
    status: ReportStatus
    findings: list[Finding]
    schema_version: str = "0.1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "envelope_id": self.envelope_id,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class TransferRisk:
    """Deterministic research score for one transfer boundary.

    The score is not a probability. It is a bounded structural risk index that
    makes model assumptions explicit for replay and comparison.
    """

    envelope_id: str
    score: float
    level: RiskLevel
    components: dict[str, float]
    model_version: str = "0.1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "envelope_id": self.envelope_id,
            "score": _round3(self.score),
            "level": self.level,
            "components": {key: _round3(value) for key, value in self.components.items()},
        }


@dataclass(frozen=True)
class TransferEdge:
    """Declared parent -> child boundary used by the v0.2 profile model."""

    parent_envelope_id: str
    child_envelope_id: str
    producer: str
    consumer: str
    trust_before: TrustLevel
    trust_after: TrustLevel
    authority_before: AuthorityScope
    authority_after: AuthorityScope

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TransferRiskProfile:
    """Multi-dimensional v0.2 risk profile for one transfer boundary."""

    envelope_id: str
    score: float
    level: RiskLevel
    dimensions: dict[str, float]
    violations: list[Finding] = field(default_factory=list)
    edge: TransferEdge | None = None
    model_version: str = "0.2"

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "envelope_id": self.envelope_id,
            "score": _round3(self.score),
            "level": self.level,
            "dimensions": {key: _round3(value) for key, value in self.dimensions.items()},
            "violations": [violation.to_dict() for violation in self.violations],
            "edge": None if self.edge is None else self.edge.to_dict(),
        }


def _round3(value: float) -> float:
    """Stable report rounding across Python versions."""

    return float(Decimal(f"{value:.12f}").quantize(Decimal("0.001"), rounding=ROUND_HALF_UP))
