"""Operator-approved, digest-only Harness adapter for Transfer Verifier.

The module is deliberately self-contained so Distribution Discovery V1 can bind one
implementation file. It never discovers packages, opens paths or the network, and it
does not retain raw transfer payloads. The embedding application supplies the exact
approved manifest and configuration bytes before constructing the extension object.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import stat
import sys
from collections.abc import Callable
from typing import Any, Final, Literal

from agentic_security_harness.extension_sdk import (
    ExtensionContractError,
    ExtensionFindingV1,
    ExtensionManifestV1,
    ExtensionObservationEnvelopeV1,
    decode_extension_manifest_v1,
)
from agentic_security_harness.portfolio_contract import CanonicalObservationEventV1

EXTENSION_ID: Final = "agentic-transfer-verifier.verification"
EXTENSION_VERSION: Final = "1.0.1"
CORE_RUNTIME_FILES: Final = (
    (
        "agentic_transfer_verifier/__init__.py",
        "81e8b1c5705098f8b812183ed9dbcc6d0bf796132e03661f76bb070191eae9d3",
    ),
    (
        "agentic_transfer_verifier/adversarial.py",
        "82548876e98ae81fe844c48c147ec0ea61c2146d194c2599344e3052a1113a16",
    ),
    (
        "agentic_transfer_verifier/asset_leakage.py",
        "2f3da31620ae491437d119000e274c11943118728b10d20dd56e77b6d96fb86f",
    ),
    (
        "agentic_transfer_verifier/models.py",
        "3d8e7631f72249c9b3957feff06f63653e97806bbc66617387d9158e8994287d",
    ),
    (
        "agentic_transfer_verifier/portfolio_adapter.py",
        "ba3de14194786e32c8830aaf544b19a0a1d460b4d909817f2fd21ccc8eca7ce0",
    ),
    (
        "agentic_transfer_verifier/risk_model.py",
        "9636e23fb44c6b2882c07509b6e3fdc6db19e5931073b746355e836360d83136",
    ),
    (
        "agentic_transfer_verifier/scenarios.py",
        "a26d28166b0ee507bee30a940e75f21fdd6eab6c599d5603eb897850296d8a39",
    ),
    (
        "agentic_transfer_verifier/verifier.py",
        "7335162fcf546ac3927e8a2f2ccb35c7102eaa7d29be53d8a41389e513a70e3d",
    ),
)
CONFIGURATION: Final = {
    "schema_version": "agentic-transfer-verifier-harness-extension-config-v1.0",
    "core_distribution": {
        "name": "agentic-transfer-verifier",
        "version": "0.2.1",
        "runtime_files": [{"path": path, "sha256": digest} for path, digest in CORE_RUNTIME_FILES],
    },
    "projection": "portfolio-observation-digest-only-v1",
    "telemetry_policy": "non-complete-inconclusive",
    "operational_authority": "none",
}
CANONICAL_CONFIGURATION_BYTES: Final = (
    json.dumps(
        CONFIGURATION,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    + b"\n"
)
CONFIGURATION_SHA256: Final = hashlib.sha256(CANONICAL_CONFIGURATION_BYTES).hexdigest()

_EXPECTED_CAPABILITIES: Final = ("observation.read", "finding.emit")
_EXPECTED_CONSUMES: Final = (("portfolio-observation", "1.0", True),)
_EXPECTED_PRODUCES: Final = (("extension-finding", "1.0", True),)
_SEVERITY_RANK: Final = {"low": 1, "medium": 2, "high": 3}
VerifierSeverity = Literal["low", "medium", "high"]
FindingOutcome = Literal["pass", "finding", "inconclusive", "error"]
FindingSeverity = Literal["none", "low", "medium", "high", "critical"]


class TransferHarnessExtensionError(ValueError):
    """Raised when explicit construction or evaluation violates the closed adapter."""


class TransferVerifierHarnessExtensionV1:
    """Evaluate digest-only observation projections with the deterministic verifier API."""

    manifest: ExtensionManifestV1
    _provenance_type: Callable[..., Any]
    _envelope_type: Callable[..., Any]
    _verifier: Callable[[Any], Any]
    _sealed: bool
    __slots__ = ("manifest", "_provenance_type", "_envelope_type", "_verifier", "_sealed")

    def __init__(self, manifest: ExtensionManifestV1) -> None:
        object.__setattr__(self, "_sealed", False)
        object.__setattr__(self, "manifest", _validate_manifest(manifest))
        _reject_loaded_core_namespace()
        verified_origins = _verify_core_distribution()
        _reject_loaded_core_namespace()
        models = importlib.import_module("agentic_transfer_verifier.models")
        verifier = importlib.import_module("agentic_transfer_verifier.verifier")
        _verify_imported_core_namespace(verified_origins)
        if _verify_core_distribution() != verified_origins:
            raise TransferHarnessExtensionError("core distribution origin changed during import")
        object.__setattr__(self, "_provenance_type", models.ProvenanceStep)
        object.__setattr__(self, "_envelope_type", models.TransferEnvelope)
        object.__setattr__(self, "_verifier", verifier.verify_envelope)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("extension instance is immutable after construction")
        object.__setattr__(self, name, value)

    def evaluate(self, envelope: ExtensionObservationEnvelopeV1) -> tuple[ExtensionFindingV1, ...]:
        try:
            checked = ExtensionObservationEnvelopeV1.model_validate(
                envelope.model_dump(mode="python")
            )
        except (AttributeError, ValueError) as exc:
            raise TransferHarnessExtensionError("extension envelope violates Harness V1") from exc

        matching = tuple(
            event for event in checked.events if event.activity.startswith("transfer.")
        )
        if not matching:
            return (
                _finding(
                    check_id="transfer.verification",
                    outcome="inconclusive",
                    severity="medium",
                    reason_code="transfer.scope_no_matching_events",
                    event_ids=(),
                ),
            )

        incomplete = tuple(
            event.event_id for event in matching if event.telemetry_state != "complete"
        )
        grouped: dict[tuple[str, VerifierSeverity], list[str]] = {}
        verified_event_ids: list[str] = []
        for event in matching:
            if event.telemetry_state != "complete":
                continue
            verified_event_ids.append(event.event_id)
            report = self._verifier(
                _digest_only_projection(
                    event,
                    provenance_type=self._provenance_type,
                    envelope_type=self._envelope_type,
                )
            )
            for item in report.findings:
                grouped.setdefault((item.code, item.severity), []).append(event.event_id)

        findings: list[ExtensionFindingV1] = []
        for code, severity in sorted(
            grouped,
            key=lambda item: (-_SEVERITY_RANK[item[1]], item[0]),
        ):
            findings.append(
                _finding(
                    check_id=f"transfer.{code}",
                    outcome="finding",
                    severity=severity,
                    reason_code=f"transfer.{code}",
                    event_ids=tuple(grouped[(code, severity)]),
                )
            )
        if incomplete:
            findings.append(
                _finding(
                    check_id="transfer.telemetry",
                    outcome="inconclusive",
                    severity="medium",
                    reason_code="transfer.telemetry_incomplete",
                    event_ids=incomplete,
                )
            )
        if not findings:
            findings.append(
                _finding(
                    check_id="transfer.verification",
                    outcome="pass",
                    severity="none",
                    reason_code="transfer.digest_projection_valid",
                    event_ids=tuple(verified_event_ids),
                )
            )
        return tuple(findings)


def build_extension(
    *,
    manifest_bytes: bytes,
    configuration_bytes: bytes,
) -> TransferVerifierHarnessExtensionV1:
    """Construct only from exact operator-retained manifest and configuration bytes."""

    if not isinstance(manifest_bytes, bytes) or not isinstance(configuration_bytes, bytes):
        raise TransferHarnessExtensionError("manifest and configuration must be bytes")
    if configuration_bytes != CANONICAL_CONFIGURATION_BYTES:
        raise TransferHarnessExtensionError("configuration bytes differ from the closed V1 profile")
    try:
        manifest = decode_extension_manifest_v1(manifest_bytes)
    except ExtensionContractError as exc:
        raise TransferHarnessExtensionError("manifest bytes violate Harness V1") from exc
    return TransferVerifierHarnessExtensionV1(manifest)


def _validate_manifest(manifest: ExtensionManifestV1) -> ExtensionManifestV1:
    try:
        checked = ExtensionManifestV1.model_validate(manifest.model_dump(mode="python"))
    except (AttributeError, ValueError) as exc:
        raise TransferHarnessExtensionError("manifest object violates Harness V1") from exc
    consumes = tuple((item.contract_id, item.version, item.required) for item in checked.consumes)
    produces = tuple((item.contract_id, item.version, item.required) for item in checked.produces)
    if (
        checked.extension_id != EXTENSION_ID
        or checked.extension_version != EXTENSION_VERSION
        or checked.component_id != "agentic-transfer-verifier"
        or checked.kind != "check_extension"
        or checked.capabilities != _EXPECTED_CAPABILITIES
        or consumes != _EXPECTED_CONSUMES
        or produces != _EXPECTED_PRODUCES
        or checked.harness_api != "1"
        or not checked.deterministic
        or checked.evidence_provenance != "producer_declared"
        or checked.network_mode != "off"
        or checked.raw_data_policy != "digests_only"
        or checked.execution_model != "in_process_operator_approved_not_sandboxed"
        or checked.operational_authority != "none"
        or checked.configuration_sha256 != CONFIGURATION_SHA256
    ):
        raise TransferHarnessExtensionError("manifest differs from the closed V1 profile")
    return checked


def _digest_only_projection(
    event: CanonicalObservationEventV1,
    *,
    provenance_type: Callable[..., Any],
    envelope_type: Callable[..., Any],
) -> Any:
    return envelope_type(
        envelope_id=event.event_id,
        producer=event.producer_id_hash,
        consumer="agentic-transfer-verifier",
        payload_kind=event.activity,
        trust_level="untrusted",
        authority_scope="none",
        payload={"data_envelope_ref": event.data_envelope_ref},
        provenance=[
            provenance_type(
                actor=event.producer_id_hash,
                action=event.activity,
                source=event.source_surface,
            )
        ],
        consumed_as="evidence",
        created_at=event.occurred_at.isoformat(),
    )


def _reject_loaded_core_namespace() -> None:
    if any(
        name == "agentic_transfer_verifier" or name.startswith("agentic_transfer_verifier.")
        for name in sys.modules
    ):
        raise TransferHarnessExtensionError(
            "core namespace was loaded before verified construction"
        )


def _verify_core_distribution() -> tuple[tuple[str, str], ...]:
    try:
        distribution = importlib.metadata.distribution("agentic-transfer-verifier")
    except importlib.metadata.PackageNotFoundError as exc:
        raise TransferHarnessExtensionError("approved core distribution is not installed") from exc
    if distribution.version != "0.2.1":
        raise TransferHarnessExtensionError("core distribution version differs from V1")
    files = distribution.files
    if files is None:
        raise TransferHarnessExtensionError("core distribution file inventory is unavailable")
    actual = tuple(
        sorted(
            str(item).replace("\\", "/")
            for item in files
            if str(item).replace("\\", "/").startswith("agentic_transfer_verifier/")
            and str(item).endswith(".py")
        )
    )
    expected = tuple(path for path, _ in CORE_RUNTIME_FILES)
    if actual != expected:
        raise TransferHarnessExtensionError("core runtime file inventory differs from V1")
    verified_origins: list[tuple[str, str]] = []
    for relative, expected_sha256 in CORE_RUNTIME_FILES:
        candidate = os.path.abspath(str(distribution.locate_file(relative)))
        try:
            before = os.lstat(candidate)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > 1_048_576
                or bool(
                    getattr(before, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                )
            ):
                raise TransferHarnessExtensionError("core runtime file is not a regular V1 file")
            with open(candidate, "rb", buffering=0) as stream:
                opened = os.fstat(stream.fileno())
                payload = stream.read(1_048_577)
                after = os.fstat(stream.fileno())
            final = os.lstat(candidate)
        except OSError as exc:
            raise TransferHarnessExtensionError("core runtime file is unavailable") from exc
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if (
            len(payload) > 1_048_576
            or identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or identity != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise TransferHarnessExtensionError("core runtime file digest or identity drift")
        verified_origins.append((_module_name_for_runtime_file(relative), candidate))
    return tuple(verified_origins)


def _module_name_for_runtime_file(relative: str) -> str:
    suffix = "/__init__.py"
    if relative.endswith(suffix):
        return relative[: -len(suffix)].replace("/", ".")
    if not relative.endswith(".py"):
        raise TransferHarnessExtensionError("core runtime file is not a Python module")
    return relative[:-3].replace("/", ".")


def _verify_imported_core_namespace(verified_origins: tuple[tuple[str, str], ...]) -> None:
    expected = dict(verified_origins)
    loaded = {
        name
        for name in sys.modules
        if name == "agentic_transfer_verifier" or name.startswith("agentic_transfer_verifier.")
    }
    if loaded != set(expected):
        raise TransferHarnessExtensionError(
            "imported core namespace differs from verified inventory"
        )
    for name, expected_origin in expected.items():
        module = sys.modules.get(name)
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            raise TransferHarnessExtensionError("imported core module origin is unavailable")
        if os.path.normcase(os.path.abspath(origin)) != os.path.normcase(expected_origin):
            raise TransferHarnessExtensionError(
                "imported core module origin differs from verified file"
            )
        try:
            if not os.path.samefile(origin, expected_origin):
                raise TransferHarnessExtensionError(
                    "imported core module identity differs from verified file"
                )
        except OSError as exc:
            raise TransferHarnessExtensionError(
                "imported core module origin is unavailable"
            ) from exc


def _finding(
    *,
    check_id: str,
    outcome: FindingOutcome,
    severity: FindingSeverity,
    reason_code: str,
    event_ids: tuple[str, ...],
) -> ExtensionFindingV1:
    return ExtensionFindingV1(
        check_id=check_id,
        outcome=outcome,
        severity=severity,
        reason_code=reason_code,
        evidence_event_ids=event_ids,
    )
