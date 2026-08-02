from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from agentic_transfer_verifier.portfolio_adapter import (
    MAX_ADAPTER_AUDIT_MAPPINGS,
    MAX_OBSERVATION_ENTITY_REFS,
    MAX_TRANSFER_COLLECTION_ITEMS,
    MAX_TRANSFER_ENVELOPE_BYTES,
    AdapterAuditV1,
    TransferAdapterContext,
    TransferEnvelopeContractError,
    load_transfer_envelope,
    project_transfer_envelope,
)

SHA = "a" * 40
DIGEST = "b" * 64
ROOT = Path(__file__).resolve().parents[1]


def _source(**updates: object) -> dict[str, object]:
    source: dict[str, object] = {
        "envelope_id": "transfer-001",
        "producer": "agent-alpha",
        "consumer": "agent-beta",
        "payload_kind": "summary",
        "trust_level": "attested",
        "authority_scope": "admin",
        "payload": {"synthetic": "bounded example"},
        "provenance": [
            {
                "actor": "agent-alpha",
                "action": "attested",
                "source": "declared-local-source",
                "timestamp": "2026-08-02T10:00:00Z",
            }
        ],
        "consumed_as": "instruction",
        "allowed_uses": ["execute"],
        "identity_claims": [
            {
                "subject": "agent-alpha",
                "issuer": "declared-issuer",
                "credential_type": "declared",
                "verified": True,
                "binding": "declared-binding",
                "expires_at": "2026-08-02T11:00:00Z",
            }
        ],
        "capabilities": [
            {
                "name": "synthetic-admin",
                "scope": "admin",
                "source": "declared-source",
                "bound_to": "declared-binding",
                "expires_at": "2026-08-02T11:00:00Z",
            }
        ],
        "created_at": "2026-08-02T10:00:00Z",
        "expires_at": "2026-08-02T11:00:00Z",
        "approval_id": "declared-approval",
        "approval_binding": "declared-action",
        "parent_envelope_id": "",
        "schema_version": "0.1",
    }
    source.update(updates)
    return source


def _encoded(**updates: object) -> bytes:
    return json.dumps(_source(**updates), ensure_ascii=False).encode("utf-8")


def _context(**updates: object) -> TransferAdapterContext:
    values: dict[str, object] = {
        "project_id": "security-project",
        "repository_id": "owner/security-project",
        "repository_sha": SHA,
        "source_surface": "agent",
        "data_envelope_ref": DIGEST,
        "telemetry_state": "complete",
    }
    values.update(updates)
    return TransferAdapterContext(**values)  # type: ignore[arg-type]


def test_strict_loader_accepts_complete_v01_and_rejects_unknown_missing_duplicate() -> None:
    envelope = load_transfer_envelope(_encoded())
    assert envelope.envelope_id == "transfer-001"
    assert envelope.schema_version == "0.1"

    unknown = _source(raw_prompt="synthetic")
    with pytest.raises(TransferEnvelopeContractError, match="fields"):
        load_transfer_envelope(json.dumps(unknown).encode())
    missing = _source()
    del missing["created_at"]
    with pytest.raises(TransferEnvelopeContractError, match="fields"):
        load_transfer_envelope(json.dumps(missing).encode())
    duplicate = _encoded().replace(
        b'"schema_version": "0.1"',
        b'"schema_version": "0.1", "schema_version": "0.1"',
    )
    with pytest.raises(TransferEnvelopeContractError, match="duplicate"):
        load_transfer_envelope(duplicate)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"created_at": ""}, "created_at is required"),
        ({"created_at": "2026-08-02T10:00:00"}, "timezone-aware"),
        ({"created_at": "not-a-time"}, "timezone-aware"),
        ({"created_at": "1969-12-31T23:59:59Z"}, "supported range"),
        ({"expires_at": "2026-08-02T09:00:00Z"}, "must follow"),
    ],
)
def test_loader_fails_closed_on_missing_invalid_or_impossible_time(
    updates: dict[str, object], message: str
) -> None:
    with pytest.raises(TransferEnvelopeContractError, match=message):
        load_transfer_envelope(_encoded(**updates))


def test_loader_rejects_wrong_nested_types_nonfinite_and_oversized_input() -> None:
    with pytest.raises(TransferEnvelopeContractError, match="wrong JSON type"):
        load_transfer_envelope(_encoded(allowed_uses="execute"))
    with pytest.raises(TransferEnvelopeContractError, match="wrong JSON type"):
        load_transfer_envelope(
            _encoded(
                identity_claims=[
                    {
                        "subject": "agent-alpha",
                        "issuer": "declared-issuer",
                        "credential_type": "declared",
                        "verified": 1,
                        "binding": "declared-binding",
                        "expires_at": "2026-08-02T11:00:00Z",
                    }
                ]
            )
        )
    nonfinite = _encoded().replace(b'"bounded example"', b'NaN')
    with pytest.raises(TransferEnvelopeContractError, match="non-finite"):
        load_transfer_envelope(nonfinite)
    deeply_nested = _encoded().replace(
        b'{"synthetic": "bounded example"}',
        b'{"nested":' + (b"[" * 1_100) + b"0" + (b"]" * 1_100) + b"}",
    )
    with pytest.raises(TransferEnvelopeContractError, match="JSON nesting|valid UTF-8 JSON"):
        load_transfer_envelope(deeply_nested)
    bounded_parser_depth = _encoded().replace(
        b'{"synthetic": "bounded example"}',
        b'{"nested":' + (b"[" * 70) + b"0" + (b"]" * 70) + b"}",
    )
    with pytest.raises(TransferEnvelopeContractError, match="JSON nesting"):
        load_transfer_envelope(bounded_parser_depth)
    with pytest.raises(TransferEnvelopeContractError, match="byte limit"):
        load_transfer_envelope(b"x" * (MAX_TRANSFER_ENVELOPE_BYTES + 1))
    with pytest.raises(TransferEnvelopeContractError, match="cardinality"):
        load_transfer_envelope(
            _encoded(allowed_uses=["read"] * (MAX_TRANSFER_COLLECTION_ITEMS + 1))
        )


@pytest.mark.parametrize(
    "updates",
    [
        {
            "provenance": [
                {
                    "actor": "agent-alpha",
                    "action": "observed",
                    "source": "synthetic",
                    "timestamp": "2100-01-01T00:00:01Z",
                }
            ]
        },
        {
            "identity_claims": [
                {
                    "subject": "agent-alpha",
                    "issuer": "declared-issuer",
                    "credential_type": "declared",
                    "verified": False,
                    "binding": "declared-binding",
                    "expires_at": "1969-12-31T23:59:59Z",
                }
            ]
        },
        {
            "capabilities": [
                {
                    "name": "synthetic-read",
                    "scope": "read",
                    "source": "declared-source",
                    "bound_to": "declared-binding",
                    "expires_at": "not-a-time",
                }
            ]
        },
    ],
)
def test_loader_applies_timestamp_bounds_to_all_nested_records(
    updates: dict[str, object],
) -> None:
    with pytest.raises(TransferEnvelopeContractError):
        load_transfer_envelope(_encoded(**updates))


def test_projection_downgrades_declared_attestation_authority_capability_and_approval() -> None:
    result = project_transfer_envelope(load_transfer_envelope(_encoded()), _context())
    event = result.observation

    assert event.schema_version == "portfolio-observation-v1.0"
    assert event.producer_attestation == "unattested"
    assert event.authority_envelope_ref is None
    assert event.operational_authority == "none"
    assert event.telemetry_state == "complete"
    assert event.entity_refs[0].kind == "artifact"
    assert set(asdict(event)) == set(result.audit.target_fields)
    serialized = json.dumps(event.to_dict(), sort_keys=True)
    serialized_result = json.dumps(asdict(result), default=str, sort_keys=True)
    for forbidden in (
        "bounded example",
        "declared-approval",
        "declared-issuer",
        "synthetic-admin",
        '"admin"',
    ):
        assert forbidden not in serialized
        assert forbidden not in serialized_result


def test_projection_audit_exhaustively_accounts_for_source_and_target_fields() -> None:
    result = project_transfer_envelope(load_transfer_envelope(_encoded()), _context())
    audit = result.audit
    mapped_sources = [field for mapping in audit.mappings for field in mapping.source_fields]
    mapped_targets = [field for mapping in audit.mappings for field in mapping.target_fields]

    assert set(mapped_sources) | set(audit.dropped_source_fields) == set(audit.source_fields)
    assert set(mapped_targets) | set(audit.context_target_fields) | set(
        audit.constant_target_fields
    ) == set(audit.target_fields)
    assert len(mapped_sources) + len(audit.dropped_source_fields) == len(audit.source_fields)
    assert (
        len(mapped_targets)
        + len(audit.context_target_fields)
        + len(audit.constant_target_fields)
        == len(audit.target_fields)
    )
    assert audit.authority_downgrade is True
    assert audit.operational_authority == "none"
    assert result.observation.to_bytes().endswith(b"\n")


def test_audit_rejects_omission_overlap_or_authority_relabelling() -> None:
    audit = project_transfer_envelope(load_transfer_envelope(_encoded()), _context()).audit
    with pytest.raises(TransferEnvelopeContractError, match="field universe"):
        replace(audit, source_fields=(*audit.source_fields, "unaccounted"))
    with pytest.raises(TransferEnvelopeContractError, match="field universe"):
        replace(audit, target_fields=audit.target_fields[:-1])
    with pytest.raises(TransferEnvelopeContractError, match="overlaps"):
        replace(audit, dropped_source_fields=(*audit.dropped_source_fields, "payload"))
    with pytest.raises(TransferEnvelopeContractError, match="downgrade"):
        AdapterAuditV1(
            **{
                **asdict(audit),
                "mappings": audit.mappings,
                "authority_downgrade": False,
            }
        )
    with pytest.raises(TransferEnvelopeContractError, match="cardinality"):
        replace(
            audit,
            mappings=audit.mappings * (MAX_ADAPTER_AUDIT_MAPPINGS + 1),
        )


def test_observation_enforces_owner_cardinality_and_wire_size_limits() -> None:
    observation = project_transfer_envelope(
        load_transfer_envelope(_encoded()), _context()
    ).observation
    pointer = observation.entity_refs[0]
    with pytest.raises(TransferEnvelopeContractError, match="cardinality"):
        replace(
            observation,
            entity_refs=(pointer,) * (MAX_OBSERVATION_ENTITY_REFS + 1),
        )
    with pytest.raises(TransferEnvelopeContractError, match="byte limit"):
        project_transfer_envelope(
            load_transfer_envelope(_encoded()),
            _context(repository_id=f"owner/{'x' * 4_096}"),
        )


def test_parent_and_payload_commitments_are_deterministic_but_payload_is_not_emitted() -> None:
    first = project_transfer_envelope(
        load_transfer_envelope(_encoded(parent_envelope_id="parent-1")), _context()
    )
    second = project_transfer_envelope(
        load_transfer_envelope(_encoded(parent_envelope_id="parent-1")), _context()
    )
    changed = project_transfer_envelope(
        load_transfer_envelope(_encoded(payload={"synthetic": "changed"})), _context()
    )

    assert first == second
    assert len(first.observation.parent_event_ids) == 1
    assert first.observation.entity_refs[0].digest != changed.observation.entity_refs[0].digest
    assert "payload" not in first.observation.to_dict()


def test_context_is_explicit_and_rejects_noncanonical_or_authority_shaped_values() -> None:
    with pytest.raises(TransferEnvelopeContractError, match="repository_id"):
        _context(repository_id="not-a-repository")
    with pytest.raises(TransferEnvelopeContractError, match="Git object"):
        _context(repository_sha="main")
    with pytest.raises(TransferEnvelopeContractError, match="data_envelope_ref"):
        _context(data_envelope_ref="trusted-policy")


def test_harness_owner_schema_bytes_and_manifest_digest_are_pinned() -> None:
    schema = ROOT / "contracts" / "portfolio-observation.v1.schema.json"
    manifest = ROOT / "contracts" / "portfolio-observation.v1.manifest.json"
    schema_data = json.loads(schema.read_text(encoding="utf-8"))
    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    pin = json.loads(
        (ROOT / "contracts" / "portfolio-observation.v1.owner-pin.json").read_text(
            encoding="utf-8"
        )
    )
    assert hashlib.sha256(schema.read_bytes()).hexdigest() == pin["schema_sha256"]
    assert pin["schema_sha256"] == (
        "19371f188b080accfdac489e985b9642f547c3300c0b56b44527eb97f550c26f"
    )
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == pin["owner_manifest_sha256"]
    assert pin["owner_manifest_sha256"] == (
        "fecbe08da3e48250aaeff2ea19bf50efdbd2c3aa532af9cae8be50b4c8321554"
    )
    assert manifest_data["schema_sha256"] == pin["schema_sha256"]
    assert manifest_data["max_bytes"] == 4_096
    assert manifest_data["max_entity_refs"] == 64
    assert manifest_data["max_parent_event_ids"] == 64
    assert manifest_data["max_adapter_fields"] == 128
    assert manifest_data["max_adapter_mappings"] == 128
    assert manifest_data["max_adapter_reason_codes"] == 64
    assert manifest_data["event_id_semantics"] == "producer_claim_shape_only"
    assert pin["operational_authority"] == "none"
    audit = project_transfer_envelope(load_transfer_envelope(_encoded()), _context()).audit
    assert set(schema_data["required"]) == set(audit.target_fields)
