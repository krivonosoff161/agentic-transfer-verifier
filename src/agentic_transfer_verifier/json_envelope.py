"""Bounded, strict JSON decoding for the public transfer envelope model."""

from __future__ import annotations

import json
import math
from dataclasses import MISSING, fields
from typing import Any

from agentic_transfer_verifier.models import (
    CapabilityGrant,
    IdentityClaim,
    ProvenanceStep,
    TransferEnvelope,
)

MAX_ENVELOPE_BYTES = 65_536
MAX_JSON_DEPTH = 64
MAX_COLLECTION_ITEMS = 64
MAX_INTEGER_DIGITS = 256


class EnvelopeInputError(ValueError):
    """Malformed envelope input; messages never include input values."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnvelopeInputError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise EnvelopeInputError("non-finite JSON number")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise EnvelopeInputError("non-finite JSON number")
    return result


def _bounded_integer(value: str) -> int:
    if len(value.lstrip("-")) > MAX_INTEGER_DIGITS:
        raise EnvelopeInputError("JSON integer digit limit exceeded")
    return int(value)


def _check_depth(root: Any) -> None:
    pending = [(root, 1)]
    while pending:
        value, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise EnvelopeInputError("JSON nesting limit exceeded")
        if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise EnvelopeInputError("invalid Unicode surrogate")
        if isinstance(value, dict):
            pending.extend((key, depth + 1) for key in value)
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)


def _object(value: Any, cls: type, where: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise EnvelopeInputError(f"{where} must be an object")
    known = {item.name for item in fields(cls)}
    required = {
        item.name for item in fields(cls)
        if item.default is MISSING and item.default_factory is MISSING
    }
    if not required <= value.keys() or not value.keys() <= known:
        raise EnvelopeInputError(f"{where} fields do not match the model")
    return value


def _string(value: Any, field: str) -> str:
    if type(value) is not str:
        raise EnvelopeInputError(f"{field} must be a string")
    return value


def _strings(value: Any, field: str) -> list[str]:
    if type(value) is not list or len(value) > MAX_COLLECTION_ITEMS:
        raise EnvelopeInputError(f"{field} must be a bounded list")
    return [_string(item, field) for item in value]


def _records(value: Any, cls: type, field: str) -> list[Any]:
    if type(value) is not list or len(value) > MAX_COLLECTION_ITEMS:
        raise EnvelopeInputError(f"{field} must be a bounded list")
    result = []
    for item in value:
        data = _object(item, cls, field + " item")
        for key, entry in data.items():
            if cls is IdentityClaim and key == "verified":
                if type(entry) is not bool:
                    raise EnvelopeInputError("identity_claims.verified must be a boolean")
            elif key == "scope":
                if _string(entry, "capabilities.scope") not in _AUTHORITY:
                    raise EnvelopeInputError("capabilities.scope has an invalid value")
            else:
                _string(entry, f"{field}.{key}")
        result.append(cls(**data))
    return result


_TRUST = {"untrusted", "tool_observed", "user_confirmed", "verified", "signed", "attested"}
_AUTHORITY = {"none", "read", "write", "execute", "admin"}
_CONSUMPTION = {"data", "evidence", "memory", "instruction", "policy", "capability_grant"}


def load_json_envelope(raw: bytes) -> TransferEnvelope:
    """Decode one envelope. Structural findings remain the verifier's responsibility."""

    if type(raw) is not bytes or len(raw) > MAX_ENVELOPE_BYTES:
        raise EnvelopeInputError("input must be bytes within the size limit")
    try:
        decoded = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            parse_int=_bounded_integer,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, EnvelopeInputError):
            raise
        raise EnvelopeInputError("invalid UTF-8 JSON") from exc
    _check_depth(decoded)
    data = _object(decoded, TransferEnvelope, "envelope")
    for key in (
        "envelope_id", "producer", "consumer", "payload_kind", "created_at", "expires_at",
        "approval_id", "approval_binding", "parent_envelope_id", "schema_version",
    ):
        if key in data:
            _string(data[key], key)
    if "schema_version" in data and data["schema_version"] != "0.1":
        raise EnvelopeInputError("unsupported envelope schema_version")
    for key, allowed in (("trust_level", _TRUST), ("authority_scope", _AUTHORITY),
                         ("consumed_as", _CONSUMPTION)):
        if key in data and _string(data[key], key) not in allowed:
            raise EnvelopeInputError(f"{key} has an invalid value")
    if type(data["payload"]) is not dict:
        raise EnvelopeInputError("payload must be an object")
    for key, cls in (("provenance", ProvenanceStep), ("identity_claims", IdentityClaim),
                     ("capabilities", CapabilityGrant)):
        if key in data:
            data[key] = _records(data[key], cls, key)
    if "allowed_uses" in data:
        data["allowed_uses"] = _strings(data["allowed_uses"], "allowed_uses")
    return TransferEnvelope(**data)
