from agentic_transfer_verifier import (
    ProvenanceStep,
    TransferEnvelope,
    assess_transfer_risk,
    verify_envelope,
)


def _base_envelope(**overrides):
    data = {
        "envelope_id": "env-1",
        "producer": "agent-a",
        "consumer": "agent-b",
        "payload_kind": "summary",
        "trust_level": "untrusted",
        "authority_scope": "none",
        "payload": {"summary": "Review docs."},
        "provenance": [ProvenanceStep(actor="user", action="created", source="chat")],
    }
    data.update(overrides)
    return TransferEnvelope(**data)


def test_valid_minimal_envelope_passes():
    report = verify_envelope(_base_envelope())

    assert report.status == "PASS"
    assert report.findings == []


def test_untrusted_authority_fails():
    report = verify_envelope(_base_envelope(authority_scope="execute"))

    assert report.status == "FAIL"
    assert [finding.code for finding in report.findings] == ["untrusted_authority"]


def test_approval_must_be_bound():
    report = verify_envelope(_base_envelope(approval_id="approval-1"))

    assert report.status == "FAIL"
    assert "unbound_approval" in {finding.code for finding in report.findings}


def test_missing_provenance_fails():
    report = verify_envelope(_base_envelope(provenance=[]))

    assert report.status == "FAIL"
    assert "missing_provenance" in {finding.code for finding in report.findings}


def test_medium_findings_warn():
    report = verify_envelope(_base_envelope(producer="agent-a", consumer="agent-a"))

    assert report.status == "WARN"
    assert "same_endpoint" in {finding.code for finding in report.findings}


def test_report_serializes_to_dict():
    report = verify_envelope(_base_envelope())

    assert report.to_dict() == {
        "schema_version": "0.1",
        "envelope_id": "env-1",
        "status": "PASS",
        "findings": [],
    }


def test_minimal_boundary_has_no_structural_risk():
    risk = assess_transfer_risk(_base_envelope())

    assert risk.score == 0
    assert risk.level == "none"
    assert risk.components == {
        "provenance_integrity": 0.0,
        "authority_movement": 0.0,
        "approval_binding": 0.0,
        "freshness": 0.0,
        "auditability": 0.0,
    }


def test_untrusted_write_transfer_scores_authority_and_approval_risk():
    risk = assess_transfer_risk(_base_envelope(authority_scope="write"))

    assert risk.level == "medium"
    assert risk.components["authority_movement"] == 0.9
    assert risk.components["approval_binding"] == 0.45
    assert risk.components["freshness"] == 0.25
    assert risk.to_dict()["score"] == 0.352


def test_missing_provenance_and_unbound_approval_raise_score():
    risk = assess_transfer_risk(
        _base_envelope(
            authority_scope="execute",
            approval_id="approval-1",
            provenance=[],
        )
    )

    assert risk.level == "high"
    assert risk.components["provenance_integrity"] == 1.0
    assert risk.components["authority_movement"] == 1.0
    assert risk.components["approval_binding"] == 1.0
    assert round(risk.score, 4) == 0.7375
    assert risk.to_dict()["score"] == 0.737


def test_partial_provenance_gap_is_fractional():
    risk = assess_transfer_risk(
        _base_envelope(
            provenance=[
                ProvenanceStep(actor="user", action="", source="chat"),
                ProvenanceStep(actor="agent-a", action="summarized", source=""),
            ]
        )
    )

    assert risk.level == "low"
    assert risk.components["provenance_integrity"] == 2 / 6
