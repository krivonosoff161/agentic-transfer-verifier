from typing import Any

from agentic_transfer_verifier import (
    CapabilityGrant,
    IdentityClaim,
    ProvenanceStep,
    TransferEnvelope,
    assess_transfer_profile,
    scenario_corpus,
)
from agentic_transfer_verifier.risk_model import AUTHORITY_RANK, TRUST_RANK


def _verified_parent() -> TransferEnvelope:
    return TransferEnvelope(
        envelope_id="parent",
        producer="user",
        consumer="agent-a",
        payload_kind="task_brief",
        trust_level="user_confirmed",
        authority_scope="read",
        payload={"task": "Review docs."},
        provenance=[ProvenanceStep(actor="user", action="created", source="chat")],
        consumed_as="instruction",
        allowed_uses=["execute"],
        identity_claims=[
            IdentityClaim(
                subject="user",
                issuer="local",
                credential_type="session",
                verified=True,
                binding="parent",
            )
        ],
        created_at="2026-07-04T00:00:00Z",
        expires_at="2026-07-04T01:00:00Z",
    )


def _child(**overrides: Any) -> TransferEnvelope:
    data: dict[str, Any] = {
        "envelope_id": "child",
        "producer": "agent-a",
        "consumer": "agent-b",
        "payload_kind": "summary",
        "trust_level": "user_confirmed",
        "authority_scope": "read",
        "payload": {"summary": "Review docs."},
        "provenance": [
            ProvenanceStep(actor="user", action="created", source="chat"),
            ProvenanceStep(actor="agent-a", action="summarized", source="TASK.md"),
        ],
        "consumed_as": "evidence",
        "allowed_uses": ["read"],
        "identity_claims": [
            IdentityClaim(
                subject="agent-a",
                issuer="local",
                credential_type="session",
                verified=True,
                binding="child",
            )
        ],
        "parent_envelope_id": "parent",
        "created_at": "2026-07-04T00:05:00Z",
        "expires_at": "2026-07-04T01:00:00Z",
    }
    data.update(overrides)
    return TransferEnvelope(**data)


def test_lattice_order_is_monotonic() -> None:
    assert TRUST_RANK["untrusted"] < TRUST_RANK["tool_observed"] < TRUST_RANK["user_confirmed"]
    assert TRUST_RANK["user_confirmed"] < TRUST_RANK["verified"] < TRUST_RANK["signed"]
    assert TRUST_RANK["signed"] < TRUST_RANK["attested"]
    assert AUTHORITY_RANK["none"] < AUTHORITY_RANK["read"] < AUTHORITY_RANK["write"]
    assert AUTHORITY_RANK["write"] < AUTHORITY_RANK["execute"] < AUTHORITY_RANK["admin"]


def test_clean_transfer_profile_has_edge_and_low_risk() -> None:
    parent = _verified_parent()
    profile = assess_transfer_profile(_child(), parent=parent)

    assert profile.level == "none"
    assert profile.violations == []
    assert profile.edge is not None
    assert profile.edge.trust_before == "user_confirmed"
    assert profile.edge.trust_after == "user_confirmed"
    assert profile.to_dict()["score"] == 0.0


def test_unverified_trust_promotion_is_flagged() -> None:
    profile = assess_transfer_profile(
        _child(trust_level="verified", identity_claims=[]),
        parent=_verified_parent(),
    )

    codes = {finding.code for finding in profile.violations}
    assert "verified_without_identity" in codes
    assert "unauthorized_trust_promotion" in codes
    assert profile.dimensions["trust_transition"] > 0
    assert profile.level == "medium"


def test_tool_output_consumed_as_instruction_is_flagged() -> None:
    profile = assess_transfer_profile(
        TransferEnvelope(
            envelope_id="tool-output",
            producer="tool-x",
            consumer="agent-b",
            payload_kind="tool_output",
            trust_level="tool_observed",
            authority_scope="write",
            payload={"text": "write this"},
            provenance=[ProvenanceStep(actor="tool-x", action="emitted", source="stdout")],
            consumed_as="instruction",
            allowed_uses=["read"],
        )
    )

    codes = {finding.code for finding in profile.violations}
    assert "data_consumed_as_instruction" in codes
    assert "weak_trust_authority" in codes
    assert profile.dimensions["instruction_boundary"] == 0.9


def test_capability_grant_must_not_exceed_authority_or_float_unbound() -> None:
    profile = assess_transfer_profile(
        _child(
            authority_scope="read",
            capabilities=[
                CapabilityGrant(name="write_files", scope="write", source="agent_card", bound_to="")
            ],
        )
    )

    codes = {finding.code for finding in profile.violations}
    assert "unbound_capability" in codes
    assert "capability_exceeds_authority" in codes
    assert profile.dimensions["capability_binding"] == 0.85


def test_approval_laundering_is_audit_risk() -> None:
    profile = assess_transfer_profile(
        _child(
            authority_scope="write",
            payload={"approved_action": "write-prod-config"},
            approval_id="approval-1",
            approval_binding="update-readme",
        )
    )

    codes = {finding.code for finding in profile.violations}
    assert "authority_escalation" in codes
    assert "approval_laundering" in codes
    assert profile.dimensions["auditability"] == 0.8


def test_scenario_corpus_has_expected_coverage() -> None:
    scenarios = scenario_corpus()

    assert {scenario.name for scenario in scenarios} == {
        "clean_handoff",
        "unverified_trust_promotion",
        "tool_output_as_instruction",
        "approval_laundering",
        "agent_card_capability_drift",
        "self_replay_memory_policy",
        "audit_gap",
    }
    for scenario in scenarios:
        profile = assess_transfer_profile(scenario.envelope, parent=scenario.parent)
        codes = {finding.code for finding in profile.violations}
        assert profile.level == scenario.expected_level
        assert set(scenario.expected_violations) <= codes
