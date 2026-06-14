from agentic_transfer_verifier import ProvenanceStep, TransferEnvelope, verify_envelope


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
