"""Deterministic transfer-envelope verifier and research risk model."""

from __future__ import annotations

from agentic_transfer_verifier.models import (
    Finding,
    RiskLevel,
    TransferEnvelope,
    TransferRisk,
    VerificationReport,
)

_AUTHORITY_RANK = {
    "none": 0,
    "read": 1,
    "write": 2,
    "execute": 3,
    "admin": 4,
}

_TRUST_RANK = {
    "untrusted": 0,
    "user_confirmed": 1,
    "tool_observed": 1,
    "verified": 2,
    "signed": 3,
    "attested": 3,
}

_RISK_WEIGHTS = {
    "provenance_integrity": 0.25,
    "authority_movement": 0.25,
    "approval_binding": 0.20,
    "freshness": 0.15,
    "auditability": 0.15,
}


def verify_envelope(envelope: TransferEnvelope) -> VerificationReport:
    """Verify one synthetic transfer envelope.

    The verifier checks structural invariants only. It does not authenticate
    real identities or perform cryptographic validation.
    """

    findings: list[Finding] = []

    if not envelope.envelope_id.strip():
        findings.append(_finding("missing_envelope_id", "high", "Envelope id is required."))
    if not envelope.producer.strip() or not envelope.consumer.strip():
        findings.append(_finding("missing_endpoint", "high", "Producer and consumer are required."))
    if envelope.producer == envelope.consumer:
        findings.append(_finding("same_endpoint", "medium", "Producer and consumer are identical."))
    if not envelope.payload_kind.strip():
        findings.append(_finding("missing_payload_kind", "medium", "Payload kind is required."))
    if not envelope.payload:
        findings.append(_finding("empty_payload", "medium", "Payload is empty."))
    if not envelope.provenance:
        findings.append(
            _finding(
                "missing_provenance",
                "high",
                "At least one provenance step is required.",
            )
        )

    if _AUTHORITY_RANK[envelope.authority_scope] > 0 and envelope.trust_level == "untrusted":
        findings.append(
            _finding(
                "untrusted_authority",
                "high",
                "Untrusted data cannot carry non-empty authority scope.",
            )
        )

    if envelope.approval_id and not envelope.approval_binding:
        findings.append(
            _finding(
                "unbound_approval",
                "high",
                "Approval id is present but not bound to a specific action or payload.",
            )
        )

    if envelope.parent_envelope_id == envelope.envelope_id and envelope.parent_envelope_id:
        findings.append(
            _finding(
                "self_parent",
                "medium",
                "Envelope cannot list itself as its parent.",
            )
        )

    if envelope.expires_at and not envelope.created_at:
        findings.append(
            _finding(
                "expiry_without_creation",
                "low",
                "Expiration timestamp exists without a creation timestamp.",
            )
        )

    status = "PASS"
    if any(f.severity == "high" for f in findings):
        status = "FAIL"
    elif findings:
        status = "WARN"
    return VerificationReport(envelope_id=envelope.envelope_id, status=status, findings=findings)


def assess_transfer_risk(envelope: TransferEnvelope) -> TransferRisk:
    """Calculate a bounded structural risk score for a transfer.

    The result is deterministic and local. It is not a statistical probability,
    a certification result, or a substitute for identity, signatures, runtime
    isolation, or policy enforcement.
    """

    components = {
        "provenance_integrity": _provenance_integrity_risk(envelope),
        "authority_movement": _authority_movement_risk(envelope),
        "approval_binding": _approval_binding_risk(envelope),
        "freshness": _freshness_risk(envelope),
        "auditability": _auditability_risk(envelope),
    }
    score = min(
        1.0,
        sum(components[name] * _RISK_WEIGHTS[name] for name in _RISK_WEIGHTS),
    )
    return TransferRisk(
        envelope_id=envelope.envelope_id,
        score=score,
        level=_risk_level(score),
        components=components,
    )


def _finding(code: str, severity: str, message: str) -> Finding:
    if severity not in {"low", "medium", "high"}:
        raise ValueError(f"invalid severity: {severity}")
    return Finding(code=code, severity=severity, message=message)  # type: ignore[arg-type]


def _provenance_integrity_risk(envelope: TransferEnvelope) -> float:
    if not envelope.provenance:
        return 1.0
    missing_fields = 0
    total_fields = len(envelope.provenance) * 3
    for step in envelope.provenance:
        missing_fields += int(not step.actor.strip())
        missing_fields += int(not step.action.strip())
        missing_fields += int(not step.source.strip())
    return missing_fields / total_fields if total_fields else 1.0


def _authority_movement_risk(envelope: TransferEnvelope) -> float:
    authority = _AUTHORITY_RANK[envelope.authority_scope]
    trust = _TRUST_RANK[envelope.trust_level]
    if authority == 0:
        return 0.0
    if trust == 0:
        return min(1.0, 0.40 + authority / 4)
    if authority >= _AUTHORITY_RANK["execute"] and trust < _TRUST_RANK["verified"]:
        return 0.60
    if authority >= _AUTHORITY_RANK["write"] and trust < _TRUST_RANK["verified"]:
        return 0.35
    return 0.10


def _approval_binding_risk(envelope: TransferEnvelope) -> float:
    authority = _AUTHORITY_RANK[envelope.authority_scope]
    if envelope.approval_id and not envelope.approval_binding:
        return 1.0
    if authority >= _AUTHORITY_RANK["write"] and not envelope.approval_id:
        return 0.45
    if envelope.approval_binding and not envelope.approval_id:
        return 0.35
    return 0.0


def _freshness_risk(envelope: TransferEnvelope) -> float:
    authority = _AUTHORITY_RANK[envelope.authority_scope]
    if envelope.expires_at and not envelope.created_at:
        return 0.40
    if authority >= _AUTHORITY_RANK["write"] and not envelope.expires_at:
        return 0.25
    if envelope.parent_envelope_id and not envelope.created_at:
        return 0.20
    return 0.0


def _auditability_risk(envelope: TransferEnvelope) -> float:
    missing = 0
    missing += int(not envelope.envelope_id.strip())
    missing += int(not envelope.producer.strip())
    missing += int(not envelope.consumer.strip())
    missing += int(not envelope.payload_kind.strip())
    missing += int(not envelope.payload)
    risk = missing / 5
    if envelope.producer == envelope.consumer and envelope.producer.strip():
        risk = max(risk, 0.35)
    if envelope.parent_envelope_id == envelope.envelope_id and envelope.parent_envelope_id:
        risk = max(risk, 0.35)
    return risk


def _risk_level(score: float) -> RiskLevel:
    if score >= 0.70:
        return "high"
    if score >= 0.35:
        return "medium"
    if score > 0:
        return "low"
    return "none"
