"""Strict downgrade-only adapter to the Security Portfolio observation V1 contract.

The canonical contract is owned by ``agentic-security-harness``.  This module keeps a
dependency-free mirror of the exact public Python shape while the owner publishes the
JSON Schema pin.  It never treats declared transfer trust, identity, approval, or
capability fields as authenticated authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

from .models import CapabilityGrant, IdentityClaim, ProvenanceStep, TransferEnvelope

TRANSFER_ENVELOPE_SCHEMA = "0.1"
PORTFOLIO_OBSERVATION_V1 = "portfolio-observation-v1.0"
PORTFOLIO_ADAPTER_AUDIT_V1 = "portfolio-adapter-audit-v1.0"
MAX_TRANSFER_ENVELOPE_BYTES = 65_536
MAX_TRANSFER_COLLECTION_ITEMS = 64
MAX_TRANSFER_JSON_NESTING = 64
MAX_PORTFOLIO_OBSERVATION_BYTES = 4_096
MAX_OBSERVATION_ENTITY_REFS = 64
MAX_OBSERVATION_PARENT_EVENTS = 64
MAX_ADAPTER_AUDIT_FIELDS = 128
MAX_ADAPTER_AUDIT_MAPPINGS = 128
MAX_ADAPTER_AUDIT_REASON_CODES = 64
MAX_SUPPORTED_TIME = datetime(2100, 1, 1, tzinfo=UTC)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_REPOSITORY_ID = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")

_SOURCE_FIELDS = (
    "envelope_id",
    "producer",
    "consumer",
    "payload_kind",
    "trust_level",
    "authority_scope",
    "payload",
    "provenance",
    "consumed_as",
    "allowed_uses",
    "identity_claims",
    "capabilities",
    "created_at",
    "expires_at",
    "approval_id",
    "approval_binding",
    "parent_envelope_id",
    "schema_version",
)
_TARGET_FIELDS = (
    "schema_version",
    "event_id",
    "project_id",
    "repository_id",
    "repository_sha",
    "occurred_at",
    "producer_id_hash",
    "producer_attestation",
    "source_surface",
    "activity",
    "entity_refs",
    "parent_event_ids",
    "data_envelope_ref",
    "authority_envelope_ref",
    "telemetry_state",
    "operational_authority",
)

SourceSurface = Literal[
    "user",
    "agent",
    "model",
    "tool",
    "mcp",
    "retrieval",
    "memory",
    "document",
    "app",
    "sensor",
    "environment",
    "provider",
    "audit",
]
TelemetryState = Literal["complete", "incomplete", "malformed", "unattested", "conflicting"]


class TransferEnvelopeContractError(ValueError):
    """Raised when source bytes or adapter context fail closed."""


@dataclass(frozen=True)
class TransferAdapterContext:
    project_id: str
    repository_id: str
    repository_sha: str
    source_surface: SourceSurface
    data_envelope_ref: str
    telemetry_state: TelemetryState = "complete"

    def __post_init__(self) -> None:
        if not _PROJECT_ID.fullmatch(self.project_id):
            raise TransferEnvelopeContractError("project_id is not canonical")
        if not _REPOSITORY_ID.fullmatch(self.repository_id):
            raise TransferEnvelopeContractError("repository_id is not canonical")
        if not _GIT_OBJECT.fullmatch(self.repository_sha):
            raise TransferEnvelopeContractError("repository_sha is not an exact Git object id")
        if self.source_surface not in {
            "user", "agent", "model", "tool", "mcp", "retrieval", "memory",
            "document", "app", "sensor", "environment", "provider", "audit",
        }:
            raise TransferEnvelopeContractError("source_surface is not supported")
        if not _SHA256.fullmatch(self.data_envelope_ref):
            raise TransferEnvelopeContractError("data_envelope_ref must be lowercase SHA-256")
        if self.telemetry_state not in {
            "complete", "incomplete", "malformed", "unattested", "conflicting",
        }:
            raise TransferEnvelopeContractError("telemetry_state is not supported")


@dataclass(frozen=True)
class SafeEvidencePointerV1:
    kind: Literal["artifact", "event", "policy", "trace", "report"]
    digest: str
    locator_id: str

    def __post_init__(self) -> None:
        if self.kind not in {"artifact", "event", "policy", "trace", "report"}:
            raise TransferEnvelopeContractError("evidence pointer kind is not supported")
        if not _SHA256.fullmatch(self.digest) or not _SHA256.fullmatch(self.locator_id):
            raise TransferEnvelopeContractError("evidence pointer values must be SHA-256")


@dataclass(frozen=True)
class CanonicalObservationV1:
    schema_version: Literal["portfolio-observation-v1.0"]
    event_id: str
    project_id: str
    repository_id: str
    repository_sha: str
    occurred_at: datetime
    producer_id_hash: str
    producer_attestation: Literal["unattested"]
    source_surface: SourceSurface
    activity: str
    entity_refs: tuple[SafeEvidencePointerV1, ...]
    parent_event_ids: tuple[str, ...]
    data_envelope_ref: str
    authority_envelope_ref: None
    telemetry_state: TelemetryState
    operational_authority: Literal["none"]

    def __post_init__(self) -> None:
        if self.schema_version != PORTFOLIO_OBSERVATION_V1:
            raise TransferEnvelopeContractError("unsupported portfolio observation version")
        if not _SHA256.fullmatch(self.event_id):
            raise TransferEnvelopeContractError("event_id must be lowercase SHA-256")
        if not _PROJECT_ID.fullmatch(self.project_id):
            raise TransferEnvelopeContractError("project_id is not canonical")
        if not _REPOSITORY_ID.fullmatch(self.repository_id):
            raise TransferEnvelopeContractError("repository_id is not canonical")
        if not _GIT_OBJECT.fullmatch(self.repository_sha):
            raise TransferEnvelopeContractError("repository_sha is not an exact Git object id")
        _validate_timestamp_value(self.occurred_at, field="occurred_at")
        if not _SHA256.fullmatch(self.producer_id_hash):
            raise TransferEnvelopeContractError("producer_id_hash must be lowercase SHA-256")
        if self.producer_attestation != "unattested":
            raise TransferEnvelopeContractError("adapter cannot authenticate the producer")
        if self.source_surface not in {
            "user", "agent", "model", "tool", "mcp", "retrieval", "memory",
            "document", "app", "sensor", "environment", "provider", "audit",
        }:
            raise TransferEnvelopeContractError("source_surface is not supported")
        if not _TOKEN.fullmatch(self.activity):
            raise TransferEnvelopeContractError("activity is not a canonical token")
        if type(self.entity_refs) is not tuple:
            raise TransferEnvelopeContractError("entity_refs must be an immutable tuple")
        if len(self.entity_refs) > MAX_OBSERVATION_ENTITY_REFS:
            raise TransferEnvelopeContractError("entity_refs exceeds the V1 cardinality limit")
        if any(type(pointer) is not SafeEvidencePointerV1 for pointer in self.entity_refs):
            raise TransferEnvelopeContractError("entity_refs must contain safe evidence pointers")
        if type(self.parent_event_ids) is not tuple:
            raise TransferEnvelopeContractError("parent_event_ids must be an immutable tuple")
        if len(self.parent_event_ids) > MAX_OBSERVATION_PARENT_EVENTS:
            raise TransferEnvelopeContractError(
                "parent_event_ids exceeds the V1 cardinality limit"
            )
        if len(self.parent_event_ids) != len(set(self.parent_event_ids)):
            raise TransferEnvelopeContractError("parent event ids must be unique")
        if any(not _SHA256.fullmatch(value) for value in self.parent_event_ids):
            raise TransferEnvelopeContractError("parent event ids must be SHA-256")
        if self.event_id in self.parent_event_ids:
            raise TransferEnvelopeContractError("event cannot be its own parent")
        if not _SHA256.fullmatch(self.data_envelope_ref):
            raise TransferEnvelopeContractError("data_envelope_ref must be SHA-256")
        if self.authority_envelope_ref is not None:
            raise TransferEnvelopeContractError("transfer adapter cannot emit authority")
        if self.telemetry_state not in {
            "complete", "incomplete", "malformed", "unattested", "conflicting",
        }:
            raise TransferEnvelopeContractError("telemetry_state is not supported")
        if self.operational_authority != "none":
            raise TransferEnvelopeContractError("transfer adapter has no operational authority")
        self.to_bytes()

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["occurred_at"] = _format_timestamp(self.occurred_at)
        return result

    def to_bytes(self) -> bytes:
        """Return the owner-defined canonical wire bytes, enforcing its size bound."""

        try:
            encoded = json.dumps(
                self.to_dict(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
        except (TypeError, ValueError, RecursionError) as exc:
            raise TransferEnvelopeContractError(
                "observation cannot be encoded as canonical JSON"
            ) from exc
        if len(encoded) > MAX_PORTFOLIO_OBSERVATION_BYTES:
            raise TransferEnvelopeContractError("observation exceeds the V1 byte limit")
        return encoded


@dataclass(frozen=True)
class AdapterFieldMappingV1:
    source_fields: tuple[str, ...]
    target_fields: tuple[str, ...]
    transformation: Literal["identity", "derived"]
    authority_effect: Literal["none", "downgrade"]

    def __post_init__(self) -> None:
        if type(self.source_fields) is not tuple or type(self.target_fields) is not tuple:
            raise TransferEnvelopeContractError("mapping fields must be immutable tuples")
        if not self.source_fields or not self.target_fields:
            raise TransferEnvelopeContractError("mapping fields must not be empty")
        if (
            len(self.source_fields) > MAX_ADAPTER_AUDIT_FIELDS
            or len(self.target_fields) > MAX_ADAPTER_AUDIT_FIELDS
        ):
            raise TransferEnvelopeContractError("mapping exceeds the V1 cardinality limit")
        if len(self.source_fields) != len(set(self.source_fields)) or len(
            self.target_fields
        ) != len(set(self.target_fields)):
            raise TransferEnvelopeContractError("mapping fields must be unique")
        if any(
            not _TOKEN.fullmatch(value)
            for value in (*self.source_fields, *self.target_fields)
        ):
            raise TransferEnvelopeContractError("mapping fields must be canonical tokens")
        if self.transformation not in {"identity", "derived"}:
            raise TransferEnvelopeContractError("mapping transformation is not supported")
        if self.authority_effect not in {"none", "downgrade"}:
            raise TransferEnvelopeContractError("mapping authority effect is not supported")
        if self.transformation == "identity" and (
            len(self.source_fields) != 1 or self.source_fields != self.target_fields
        ):
            raise TransferEnvelopeContractError("identity mapping requires one identical field")


@dataclass(frozen=True)
class AdapterAuditV1:
    schema_version: Literal["portfolio-adapter-audit-v1.0"]
    source_model: Literal["transfer_verifier.transfer_envelope"]
    target_model: Literal["portfolio-observation-v1.0"]
    completeness: Literal["partial"]
    source_fields: tuple[str, ...]
    target_fields: tuple[str, ...]
    mappings: tuple[AdapterFieldMappingV1, ...]
    dropped_source_fields: tuple[str, ...]
    context_target_fields: tuple[str, ...]
    constant_target_fields: tuple[str, ...]
    authority_downgrade: Literal[True]
    reason_codes: tuple[str, ...]
    operational_authority: Literal["none"]

    def __post_init__(self) -> None:
        if self.schema_version != PORTFOLIO_ADAPTER_AUDIT_V1:
            raise TransferEnvelopeContractError("unsupported adapter audit version")
        if self.source_model != "transfer_verifier.transfer_envelope":
            raise TransferEnvelopeContractError("unsupported adapter source model")
        if self.target_model != PORTFOLIO_OBSERVATION_V1:
            raise TransferEnvelopeContractError("unsupported adapter target model")
        if self.completeness != "partial":
            raise TransferEnvelopeContractError("transfer projection must remain partial")
        if self.source_fields != _SOURCE_FIELDS:
            raise TransferEnvelopeContractError(
                "source_fields must equal the TransferEnvelope field universe"
            )
        if self.target_fields != _TARGET_FIELDS:
            raise TransferEnvelopeContractError(
                "target_fields must equal the canonical observation field universe"
            )
        listed_groups = (
            self.source_fields,
            self.target_fields,
            self.dropped_source_fields,
            self.context_target_fields,
            self.constant_target_fields,
            self.reason_codes,
        )
        if any(len(group) != len(set(group)) for group in listed_groups):
            raise TransferEnvelopeContractError("adapter audit field lists must be unique")
        if (
            len(self.source_fields) > MAX_ADAPTER_AUDIT_FIELDS
            or len(self.target_fields) > MAX_ADAPTER_AUDIT_FIELDS
            or len(self.dropped_source_fields) > MAX_ADAPTER_AUDIT_FIELDS
            or len(self.context_target_fields) > MAX_ADAPTER_AUDIT_FIELDS
            or len(self.constant_target_fields) > MAX_ADAPTER_AUDIT_FIELDS
            or len(self.mappings) > MAX_ADAPTER_AUDIT_MAPPINGS
            or len(self.reason_codes) > MAX_ADAPTER_AUDIT_REASON_CODES
        ):
            raise TransferEnvelopeContractError("adapter audit exceeds a V1 cardinality limit")
        if type(self.mappings) is not tuple or any(
            type(item) is not AdapterFieldMappingV1 for item in self.mappings
        ):
            raise TransferEnvelopeContractError("mappings must contain typed immutable records")
        if any(not _TOKEN.fullmatch(value) for group in listed_groups for value in group):
            raise TransferEnvelopeContractError("adapter audit values must be canonical tokens")
        mapped_sources = [field for item in self.mappings for field in item.source_fields]
        mapped_targets = [field for item in self.mappings for field in item.target_fields]
        source_accounting = mapped_sources + list(self.dropped_source_fields)
        target_accounting = (
            mapped_targets + list(self.context_target_fields) + list(self.constant_target_fields)
        )
        if len(source_accounting) != len(set(source_accounting)):
            raise TransferEnvelopeContractError("source field accounting overlaps")
        if len(target_accounting) != len(set(target_accounting)):
            raise TransferEnvelopeContractError("target field accounting overlaps")
        if set(source_accounting) != set(self.source_fields):
            raise TransferEnvelopeContractError("source field accounting is not exhaustive")
        if set(target_accounting) != set(self.target_fields):
            raise TransferEnvelopeContractError("target field accounting is not exhaustive")
        if not self.reason_codes:
            raise TransferEnvelopeContractError("partial projection requires reason codes")
        if not self.authority_downgrade or self.operational_authority != "none":
            raise TransferEnvelopeContractError("projection must downgrade authority")
        if "authority_envelope_ref" not in self.constant_target_fields:
            raise TransferEnvelopeContractError("authority_envelope_ref must be constant")
        if "operational_authority" not in self.constant_target_fields:
            raise TransferEnvelopeContractError("operational_authority must be constant")


@dataclass(frozen=True)
class TransferProjectionResult:
    observation: CanonicalObservationV1
    audit: AdapterAuditV1


def load_transfer_envelope(payload: bytes) -> TransferEnvelope:
    """Strictly decode the existing complete TransferEnvelope JSON representation."""

    if not isinstance(payload, bytes):
        raise TransferEnvelopeContractError("transfer envelope payload must be bytes")
    if len(payload) > MAX_TRANSFER_ENVELOPE_BYTES:
        raise TransferEnvelopeContractError("transfer envelope exceeds the byte limit")
    try:
        decoded = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TransferEnvelopeContractError("transfer envelope is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, dict):
        raise TransferEnvelopeContractError("transfer envelope must be a JSON object")
    _ensure_json_nesting(decoded)
    _require_exact_fields(decoded, _SOURCE_FIELDS, where="transfer envelope")
    _require_exact_type(decoded["schema_version"], str, field="schema_version")
    if decoded["schema_version"] != TRANSFER_ENVELOPE_SCHEMA:
        raise TransferEnvelopeContractError("unsupported transfer envelope schema")

    string_fields = (
        "envelope_id", "producer", "consumer", "payload_kind", "trust_level",
        "authority_scope", "consumed_as", "created_at", "expires_at", "approval_id",
        "approval_binding", "parent_envelope_id",
    )
    for field in string_fields:
        _require_exact_type(decoded[field], str, field=field)
    for field in ("envelope_id", "producer", "consumer", "payload_kind"):
        if not cast(str, decoded[field]).strip():
            raise TransferEnvelopeContractError(f"{field} must not be empty")
    if not _TOKEN.fullmatch(cast(str, decoded["payload_kind"])):
        raise TransferEnvelopeContractError("payload_kind is not a canonical token")
    if decoded["trust_level"] not in {
        "untrusted", "tool_observed", "user_confirmed", "verified", "signed", "attested",
    }:
        raise TransferEnvelopeContractError("trust_level is not supported")
    if decoded["authority_scope"] not in {"none", "read", "write", "execute", "admin"}:
        raise TransferEnvelopeContractError("authority_scope is not supported")
    if decoded["consumed_as"] not in {
        "data", "evidence", "memory", "instruction", "policy", "capability_grant",
    }:
        raise TransferEnvelopeContractError("consumed_as is not supported")
    _require_exact_type(decoded["payload"], dict, field="payload")
    if not decoded["payload"]:
        raise TransferEnvelopeContractError("payload must not be empty")
    for field in ("provenance", "allowed_uses", "identity_claims", "capabilities"):
        _require_exact_type(decoded[field], list, field=field)
        if len(cast(list[object], decoded[field])) > MAX_TRANSFER_COLLECTION_ITEMS:
            raise TransferEnvelopeContractError(f"{field} exceeds the cardinality limit")
    if any(type(value) is not str for value in decoded["allowed_uses"]):
        raise TransferEnvelopeContractError("allowed_uses must contain only strings")

    provenance = [_load_provenance(value) for value in decoded["provenance"]]
    identities = [_load_identity(value) for value in decoded["identity_claims"]]
    capabilities = [_load_capability(value) for value in decoded["capabilities"]]
    created_at = _parse_required_timestamp(cast(str, decoded["created_at"]), field="created_at")
    expires_at_text = cast(str, decoded["expires_at"])
    if expires_at_text:
        expires_at = _parse_required_timestamp(expires_at_text, field="expires_at")
        if expires_at <= created_at:
            raise TransferEnvelopeContractError("expires_at must follow created_at")

    return TransferEnvelope(
        envelope_id=cast(str, decoded["envelope_id"]),
        producer=cast(str, decoded["producer"]),
        consumer=cast(str, decoded["consumer"]),
        payload_kind=cast(str, decoded["payload_kind"]),
        trust_level=cast(Any, decoded["trust_level"]),
        authority_scope=cast(Any, decoded["authority_scope"]),
        payload=cast(dict[str, Any], decoded["payload"]),
        provenance=provenance,
        consumed_as=cast(Any, decoded["consumed_as"]),
        allowed_uses=cast(list[str], decoded["allowed_uses"]),
        identity_claims=identities,
        capabilities=capabilities,
        created_at=cast(str, decoded["created_at"]),
        expires_at=expires_at_text,
        approval_id=cast(str, decoded["approval_id"]),
        approval_binding=cast(str, decoded["approval_binding"]),
        parent_envelope_id=cast(str, decoded["parent_envelope_id"]),
        schema_version=TRANSFER_ENVELOPE_SCHEMA,
    )


def project_transfer_envelope(
    envelope: TransferEnvelope,
    context: TransferAdapterContext,
) -> TransferProjectionResult:
    """Project declared transfer data without promoting trust, identity, or authority."""

    occurred_at = _parse_required_timestamp(envelope.created_at, field="created_at")
    payload_bytes = _canonical_json_bytes(envelope.payload)
    payload_digest = hashlib.sha256(payload_bytes).hexdigest()
    event_id = _domain_digest("transfer-envelope-id", envelope.envelope_id)
    producer_id_hash = _domain_digest("transfer-producer", envelope.producer)
    locator_id = _domain_digest("transfer-payload-locator", payload_digest)
    parent_ids = (
        ()
        if not envelope.parent_envelope_id
        else (_domain_digest("transfer-envelope-id", envelope.parent_envelope_id),)
    )
    activity = f"transfer.{envelope.consumed_as}.{envelope.payload_kind}"
    if not _TOKEN.fullmatch(activity):
        raise TransferEnvelopeContractError("derived activity is not canonical")

    observation = CanonicalObservationV1(
        schema_version="portfolio-observation-v1.0",
        event_id=event_id,
        project_id=context.project_id,
        repository_id=context.repository_id,
        repository_sha=context.repository_sha,
        occurred_at=occurred_at,
        producer_id_hash=producer_id_hash,
        producer_attestation="unattested",
        source_surface=context.source_surface,
        activity=activity,
        entity_refs=(
            SafeEvidencePointerV1(kind="artifact", digest=payload_digest, locator_id=locator_id),
        ),
        parent_event_ids=parent_ids,
        data_envelope_ref=context.data_envelope_ref,
        authority_envelope_ref=None,
        telemetry_state=context.telemetry_state,
        operational_authority="none",
    )
    mappings = (
        AdapterFieldMappingV1(("envelope_id",), ("event_id",), "derived", "downgrade"),
        AdapterFieldMappingV1(("producer",), ("producer_id_hash",), "derived", "downgrade"),
        AdapterFieldMappingV1(
            ("payload_kind", "consumed_as"), ("activity",), "derived", "downgrade"
        ),
        AdapterFieldMappingV1(("payload",), ("entity_refs",), "derived", "downgrade"),
        AdapterFieldMappingV1(("created_at",), ("occurred_at",), "derived", "none"),
        AdapterFieldMappingV1(
            ("parent_envelope_id",), ("parent_event_ids",), "derived", "downgrade"
        ),
    )
    audit = AdapterAuditV1(
        schema_version="portfolio-adapter-audit-v1.0",
        source_model="transfer_verifier.transfer_envelope",
        target_model="portfolio-observation-v1.0",
        completeness="partial",
        source_fields=_SOURCE_FIELDS,
        target_fields=_TARGET_FIELDS,
        mappings=mappings,
        dropped_source_fields=(
            "consumer",
            "trust_level",
            "authority_scope",
            "provenance",
            "allowed_uses",
            "identity_claims",
            "capabilities",
            "expires_at",
            "approval_id",
            "approval_binding",
            "schema_version",
        ),
        context_target_fields=(
            "project_id",
            "repository_id",
            "repository_sha",
            "source_surface",
            "data_envelope_ref",
            "telemetry_state",
        ),
        constant_target_fields=(
            "schema_version",
            "producer_attestation",
            "authority_envelope_ref",
            "operational_authority",
        ),
        authority_downgrade=True,
        reason_codes=(
            "adapter.approval_not_consent",
            "adapter.authority_dropped",
            "adapter.capabilities_dropped",
            "adapter.declared_identity_unattested",
            "adapter.declared_trust_unattested",
            "adapter.provenance_unattested",
            "adapter.raw_payload_digest_only",
        ),
        operational_authority="none",
    )
    return TransferProjectionResult(observation=observation, audit=audit)


def _load_provenance(value: object) -> ProvenanceStep:
    _require_exact_type(value, dict, field="provenance item")
    item = cast(dict[str, object], value)
    _require_exact_fields(item, ("actor", "action", "source", "timestamp"), where="provenance")
    for field in item:
        _require_exact_type(item[field], str, field=f"provenance.{field}")
    if item["timestamp"]:
        _parse_required_timestamp(cast(str, item["timestamp"]), field="provenance.timestamp")
    return ProvenanceStep(**cast(dict[str, str], item))


def _load_identity(value: object) -> IdentityClaim:
    _require_exact_type(value, dict, field="identity claim")
    item = cast(dict[str, object], value)
    fields = ("subject", "issuer", "credential_type", "verified", "binding", "expires_at")
    _require_exact_fields(item, fields, where="identity claim")
    for field in fields:
        expected = bool if field == "verified" else str
        _require_exact_type(item[field], expected, field=f"identity_claims.{field}")
    if item["expires_at"]:
        _parse_required_timestamp(cast(str, item["expires_at"]), field="identity_claims.expires_at")
    return IdentityClaim(**cast(Any, item))


def _load_capability(value: object) -> CapabilityGrant:
    _require_exact_type(value, dict, field="capability")
    item = cast(dict[str, object], value)
    fields = ("name", "scope", "source", "bound_to", "expires_at")
    _require_exact_fields(item, fields, where="capability")
    for field in fields:
        _require_exact_type(item[field], str, field=f"capabilities.{field}")
    if item["scope"] not in {"none", "read", "write", "execute", "admin"}:
        raise TransferEnvelopeContractError("capability scope is not supported")
    if item["expires_at"]:
        _parse_required_timestamp(cast(str, item["expires_at"]), field="capabilities.expires_at")
    return CapabilityGrant(**cast(Any, item))


def _parse_required_timestamp(value: str, *, field: str) -> datetime:
    if not value:
        raise TransferEnvelopeContractError(f"{field} is required")
    if not value.endswith("Z") and not re.search(r"[+-]\d{2}:\d{2}$", value):
        raise TransferEnvelopeContractError(f"{field} must be timezone-aware RFC 3339")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransferEnvelopeContractError(f"{field} is not a valid timestamp") from exc
    _validate_timestamp_value(parsed, field=field)
    return parsed.astimezone(UTC)


def _validate_timestamp_value(value: datetime, *, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise TransferEnvelopeContractError(f"{field} must be timezone-aware")
    normalized = value.astimezone(UTC)
    if normalized.year < 1970 or normalized > MAX_SUPPORTED_TIME:
        raise TransferEnvelopeContractError(f"{field} is outside the supported range")


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise TransferEnvelopeContractError("payload is not canonical JSON data") from exc


def _domain_digest(domain: str, value: str) -> str:
    return hashlib.sha256(f"agentic-transfer-verifier/{domain}\0{value}".encode()).hexdigest()


def _require_exact_fields(value: dict[str, object], fields: tuple[str, ...], *, where: str) -> None:
    if set(value) != set(fields):
        raise TransferEnvelopeContractError(f"{where} fields do not match the contract")


def _require_exact_type(value: object, expected: type[object], *, field: str) -> None:
    if type(value) is not expected:
        raise TransferEnvelopeContractError(f"{field} has the wrong JSON type")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TransferEnvelopeContractError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise TransferEnvelopeContractError(f"non-finite JSON value is forbidden: {value}")


def _ensure_json_nesting(value: object) -> None:
    """Reject parser-dependent excessive nesting without recursive traversal."""

    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_TRANSFER_JSON_NESTING:
            raise TransferEnvelopeContractError("transfer envelope JSON nesting exceeds limit")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
