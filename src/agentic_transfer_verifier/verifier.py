"""Deterministic transfer-envelope verifier."""

from __future__ import annotations

from agentic_transfer_verifier.models import Finding, TransferEnvelope, VerificationReport

_AUTHORITY_RANK = {
    "none": 0,
    "read": 1,
    "write": 2,
    "execute": 3,
    "admin": 4,
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


def _finding(code: str, severity: str, message: str) -> Finding:
    if severity not in {"low", "medium", "high"}:
        raise ValueError(f"invalid severity: {severity}")
    return Finding(code=code, severity=severity, message=message)  # type: ignore[arg-type]
