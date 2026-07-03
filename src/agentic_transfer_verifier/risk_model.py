"""Formal transfer risk profile model v0.2."""

from __future__ import annotations

from agentic_transfer_verifier.models import (
    AuthorityScope,
    Finding,
    RiskLevel,
    TransferEdge,
    TransferEnvelope,
    TransferRiskProfile,
    TrustLevel,
)
from agentic_transfer_verifier.verifier import assess_transfer_risk

TRUST_RANK: dict[TrustLevel, int] = {
    "untrusted": 0,
    "tool_observed": 1,
    "user_confirmed": 2,
    "verified": 3,
    "signed": 4,
    "attested": 5,
}

AUTHORITY_RANK: dict[AuthorityScope, int] = {
    "none": 0,
    "read": 1,
    "write": 2,
    "execute": 3,
    "admin": 4,
}

PROFILE_WEIGHTS = {
    "provenance": 0.15,
    "identity": 0.12,
    "trust_transition": 0.14,
    "authority_transition": 0.15,
    "capability_binding": 0.12,
    "freshness_replay": 0.10,
    "instruction_boundary": 0.12,
    "auditability": 0.10,
}

INSTRUCTION_LIKE_MODES = {"instruction", "policy", "capability_grant"}
DATA_LIKE_KINDS = {
    "tool_output",
    "memory",
    "summary",
    "ocr_transcript",
    "asr_transcript",
    "browser_page",
    "agent_card",
}


def assess_transfer_profile(
    envelope: TransferEnvelope,
    *,
    parent: TransferEnvelope | None = None,
) -> TransferRiskProfile:
    """Assess a transfer boundary using the v0.2 multi-dimensional profile.

    This model is deterministic and structural. It checks declared fields and an
    optional parent envelope; it does not authenticate real identities or verify
    cryptographic material.
    """

    violations: list[Finding] = []
    edge = _edge(parent, envelope) if parent else None
    dimensions = {
        "provenance": _provenance_dimension(envelope, violations),
        "identity": _identity_dimension(envelope, violations),
        "trust_transition": _trust_transition_dimension(parent, envelope, violations),
        "authority_transition": _authority_transition_dimension(parent, envelope, violations),
        "capability_binding": _capability_dimension(envelope, violations),
        "freshness_replay": _freshness_replay_dimension(parent, envelope, violations),
        "instruction_boundary": _instruction_boundary_dimension(envelope, violations),
        "auditability": _auditability_dimension(envelope, violations),
    }
    score = min(1.0, sum(dimensions[key] * PROFILE_WEIGHTS[key] for key in PROFILE_WEIGHTS))
    return TransferRiskProfile(
        envelope_id=envelope.envelope_id,
        score=score,
        level=_risk_level(score),
        dimensions=dimensions,
        violations=violations,
        edge=edge,
    )


def _edge(parent: TransferEnvelope, child: TransferEnvelope) -> TransferEdge:
    return TransferEdge(
        parent_envelope_id=parent.envelope_id,
        child_envelope_id=child.envelope_id,
        producer=child.producer,
        consumer=child.consumer,
        trust_before=parent.trust_level,
        trust_after=child.trust_level,
        authority_before=parent.authority_scope,
        authority_after=child.authority_scope,
    )


def _provenance_dimension(envelope: TransferEnvelope, violations: list[Finding]) -> float:
    v01 = assess_transfer_risk(envelope).components["provenance_integrity"]
    if v01 >= 1.0:
        violations.append(
            _finding("profile_missing_provenance", "high", "Transfer has no provenance chain.")
        )
    elif v01 > 0:
        violations.append(
            _finding(
                "profile_partial_provenance",
                "medium",
                "One or more provenance steps are missing actor, action, or source.",
            )
        )
    return v01


def _identity_dimension(envelope: TransferEnvelope, violations: list[Finding]) -> float:
    if not envelope.identity_claims:
        if TRUST_RANK[envelope.trust_level] >= TRUST_RANK["verified"]:
            violations.append(
                _finding(
                    "verified_without_identity",
                    "high",
                    "Verified, signed, or attested transfer has no identity claim.",
                )
            )
            return 0.90
        if envelope.payload_kind == "agent_card":
            violations.append(
                _finding(
                    "agent_card_without_identity",
                    "medium",
                    "Agent card is consumed without a verifiable agent identity claim.",
                )
            )
            return 0.30
        return 0.0

    risk = 0.0
    verified_claims = [claim for claim in envelope.identity_claims if claim.verified]
    if not verified_claims:
        risk = max(risk, 0.70)
        violations.append(
            _finding(
                "unverified_identity_claim",
                "high",
                "Identity claims are present but unverified.",
            )
        )

    for claim in envelope.identity_claims:
        if not claim.subject.strip():
            risk = max(risk, 0.70)
        if claim.subject and claim.subject not in {envelope.producer, envelope.consumer}:
            risk = max(risk, 0.40)
            violations.append(
                _finding(
                    "identity_subject_mismatch",
                    "medium",
                    "Identity claim subject is not bound to producer or consumer.",
                )
            )
        if claim.verified and not claim.binding.strip():
            risk = max(risk, 0.35)
            violations.append(
                _finding(
                    "identity_without_binding",
                    "medium",
                    "Verified identity claim is not bound to the envelope or agent record.",
                )
            )
    return risk


def _trust_transition_dimension(
    parent: TransferEnvelope | None,
    envelope: TransferEnvelope,
    violations: list[Finding],
) -> float:
    if parent is None:
        return 0.0
    before = TRUST_RANK[parent.trust_level]
    after = TRUST_RANK[envelope.trust_level]
    if after <= before:
        return 0.0
    has_verifier = any(
        step.action in {"verified", "attested", "signed"} for step in envelope.provenance
    )
    has_identity = any(claim.verified for claim in envelope.identity_claims)
    if has_verifier and has_identity:
        return 0.10
    violations.append(
        _finding(
            "unauthorized_trust_promotion",
            "high",
            "Trust level increased without both verifier provenance and verified identity.",
        )
    )
    return min(1.0, 0.50 + (after - before) * 0.22)


def _authority_transition_dimension(
    parent: TransferEnvelope | None,
    envelope: TransferEnvelope,
    violations: list[Finding],
) -> float:
    current = AUTHORITY_RANK[envelope.authority_scope]
    previous = AUTHORITY_RANK[parent.authority_scope] if parent else 0
    if current == 0:
        return 0.0
    risk = 0.0
    if current > previous:
        risk = max(risk, min(1.0, 0.35 + (current - previous) * 0.16))
        violations.append(
            _finding(
                "authority_escalation",
                "high",
                "Authority increased across the transfer boundary.",
            )
        )
    if (
        envelope.trust_level in {"untrusted", "tool_observed"}
        and current >= AUTHORITY_RANK["write"]
    ):
        risk = max(risk, 0.85)
        violations.append(
            _finding(
                "weak_trust_authority",
                "high",
                "Write or stronger authority is attached to weakly trusted data.",
            )
        )
    return risk


def _capability_dimension(envelope: TransferEnvelope, violations: list[Finding]) -> float:
    if not envelope.capabilities:
        return 0.0
    risk = 0.0
    envelope_authority = AUTHORITY_RANK[envelope.authority_scope]
    for capability in envelope.capabilities:
        capability_scope = AUTHORITY_RANK[capability.scope]
        if not capability.name.strip() or not capability.source.strip():
            risk = max(risk, 0.50)
        if not capability.bound_to.strip():
            risk = max(risk, 0.75)
            violations.append(
                _finding(
                    "unbound_capability",
                    "high",
                    "Capability grant is not bound to a specific action, envelope, or approval.",
                )
            )
        if capability_scope > envelope_authority:
            risk = max(risk, 0.85)
            violations.append(
                _finding(
                    "capability_exceeds_authority",
                    "high",
                    "Capability scope exceeds the envelope authority scope.",
                )
            )
        if capability_scope >= AUTHORITY_RANK["write"] and not capability.expires_at:
            risk = max(risk, 0.45)
    return risk


def _freshness_replay_dimension(
    parent: TransferEnvelope | None,
    envelope: TransferEnvelope,
    violations: list[Finding],
) -> float:
    risk = assess_transfer_risk(envelope).components["freshness"]
    if envelope.parent_envelope_id and envelope.parent_envelope_id == envelope.envelope_id:
        risk = max(risk, 0.75)
        violations.append(
            _finding("self_replay", "high", "Envelope declares itself as its parent.")
        )
    if parent and envelope.parent_envelope_id and envelope.parent_envelope_id != parent.envelope_id:
        risk = max(risk, 0.60)
        violations.append(
            _finding(
                "parent_mismatch",
                "high",
                "Declared parent envelope does not match the supplied parent context.",
            )
        )
    if (
        AUTHORITY_RANK[envelope.authority_scope] >= AUTHORITY_RANK["write"]
        and not envelope.expires_at
    ):
        risk = max(risk, 0.45)
    return risk


def _instruction_boundary_dimension(
    envelope: TransferEnvelope,
    violations: list[Finding],
) -> float:
    if envelope.payload_kind in DATA_LIKE_KINDS and envelope.consumed_as in INSTRUCTION_LIKE_MODES:
        violations.append(
            _finding(
                "data_consumed_as_instruction",
                "high",
                "Data-like payload is consumed as instruction, policy, or capability grant.",
            )
        )
        return 0.90
    if envelope.consumed_as in INSTRUCTION_LIKE_MODES and "execute" not in envelope.allowed_uses:
        violations.append(
            _finding(
                "instruction_use_not_allowed",
                "medium",
                "Instruction-like consumption is not listed in allowed uses.",
            )
        )
        return 0.50
    return 0.0


def _auditability_dimension(envelope: TransferEnvelope, violations: list[Finding]) -> float:
    risk = assess_transfer_risk(envelope).components["auditability"]
    if envelope.approval_id and envelope.approval_binding:
        approved_action = str(envelope.payload.get("approved_action") or "")
        if approved_action and approved_action != envelope.approval_binding:
            risk = max(risk, 0.80)
            violations.append(
                _finding(
                    "approval_laundering",
                    "high",
                    "Approval binding does not match the action declared in payload.",
                )
            )
    if envelope.approval_binding and not envelope.approval_id:
        risk = max(risk, 0.45)
    return risk


def _risk_level(score: float) -> RiskLevel:
    if score >= 0.55:
        return "high"
    if score >= 0.20:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _finding(code: str, severity: str, message: str) -> Finding:
    if severity not in {"low", "medium", "high"}:
        raise ValueError(f"invalid severity: {severity}")
    return Finding(code=code, severity=severity, message=message)  # type: ignore[arg-type]
