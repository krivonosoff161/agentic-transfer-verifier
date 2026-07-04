"""Private asset leakage model for agentic transfer sinks.

The examples in this module use synthetic canary assets only. They do not model
real trading strategies, provider credentials, or live target behavior.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from agentic_transfer_verifier.models import Finding, ProvenanceStep, RiskLevel, TransferEnvelope
from agentic_transfer_verifier.risk_model import assess_transfer_profile

SensitivityLevel = Literal["public", "internal", "confidential", "restricted", "secret"]
AssetType = Literal[
    "trading_signal",
    "strategy_card",
    "credential",
    "customer_data",
    "source_code",
    "audit_trace",
]
SinkType = Literal[
    "internal_validator",
    "paper_executor",
    "private_subscriber_channel",
    "training_export",
    "agent_memory",
    "handoff_file",
    "debug_trace",
    "public_report",
    "external_llm_context",
    "git_issue_or_pr",
    "telemetry",
]

PUBLIC_SINKS: set[SinkType] = {
    "public_report",
    "external_llm_context",
    "git_issue_or_pr",
    "telemetry",
}
PERSISTENT_SINKS: set[SinkType] = {
    "agent_memory",
    "handoff_file",
    "debug_trace",
    "training_export",
    "git_issue_or_pr",
}
HIGH_SENSITIVITY = {"confidential", "restricted", "secret"}

LEAKAGE_WEIGHTS = {
    "sink_policy": 0.30,
    "redaction": 0.22,
    "persistence": 0.14,
    "external_exposure": 0.16,
    "role_confusion": 0.10,
    "traceability": 0.08,
}


@dataclass(frozen=True)
class ProtectedAsset:
    """A private asset whose movement across sinks must be controlled."""

    asset_id: str
    asset_type: AssetType
    sensitivity: SensitivityLevel
    label: str
    allowed_sinks: tuple[SinkType, ...]
    forbidden_sinks: tuple[SinkType, ...] = ()
    redaction_required: bool = False
    redacted_fields: tuple[str, ...] = ()
    canary_id: str = ""
    content_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SinkAttempt:
    """One attempted movement of a protected asset into an output sink."""

    name: str
    asset: ProtectedAsset
    envelope: TransferEnvelope
    sink: SinkType
    redaction_applied: bool
    approval_scope: str = ""
    public_safe_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "asset": self.asset.to_dict(),
            "envelope": self.envelope.to_dict(),
            "sink": self.sink,
            "redaction_applied": self.redaction_applied,
            "approval_scope": self.approval_scope,
            "public_safe_summary": self.public_safe_summary,
        }


@dataclass(frozen=True)
class SinkAssessment:
    """Deterministic assessment of one asset -> sink transfer."""

    attempt_name: str
    score: float
    level: RiskLevel
    dimensions: dict[str, float]
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    model_version: str = "0.2-asset-leakage"

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "attempt_name": self.attempt_name,
            "score": round(self.score, 3),
            "level": self.level,
            "dimensions": {key: round(value, 3) for key, value in self.dimensions.items()},
            "findings": [finding.to_dict() for finding in self.findings],
        }


def assess_sink_attempt(attempt: SinkAttempt) -> SinkAssessment:
    """Assess whether a protected asset moved into an unsafe sink."""

    findings: list[Finding] = []
    dimensions = {
        "sink_policy": _sink_policy_dimension(attempt, findings),
        "redaction": _redaction_dimension(attempt, findings),
        "persistence": _persistence_dimension(attempt, findings),
        "external_exposure": _external_exposure_dimension(attempt, findings),
        "role_confusion": _role_confusion_dimension(attempt, findings),
        "traceability": _traceability_dimension(attempt, findings),
    }
    transfer_profile = assess_transfer_profile(attempt.envelope)
    score = min(
        1.0,
        sum(dimensions[key] * LEAKAGE_WEIGHTS[key] for key in LEAKAGE_WEIGHTS)
        + 0.10 * transfer_profile.score,
    )
    findings.extend(
        finding
        for finding in transfer_profile.violations
        if finding.code in {"profile_missing_provenance", "data_consumed_as_instruction"}
    )
    return SinkAssessment(
        attempt_name=attempt.name,
        score=score,
        level=_risk_level(score),
        dimensions=dimensions,
        findings=tuple(findings),
    )


def leakage_scenario_corpus() -> list[SinkAttempt]:
    """Return synthetic private-asset leakage cases."""

    asset = trading_signal_canary()
    return [
        SinkAttempt(
            name="allowed_private_subscriber_signal",
            asset=asset,
            envelope=_signal_envelope(
                "allowed-private-subscriber",
                "paper_telegram_preview",
                "private_subscriber_channel",
            ),
            sink="private_subscriber_channel",
            redaction_applied=False,
            approval_scope="private_subscriber_channel",
            public_safe_summary="Validated canary signal moves to the allowed private channel.",
        ),
        SinkAttempt(
            name="public_report_unredacted_signal",
            asset=asset,
            envelope=_signal_envelope("public-report-leak", "agent-b", "public_report"),
            sink="public_report",
            redaction_applied=False,
            approval_scope="private_subscriber_channel",
            public_safe_summary="Canary signal is copied into a public report without redaction.",
        ),
        SinkAttempt(
            name="external_llm_context_signal",
            asset=asset,
            envelope=_signal_envelope(
                "external-llm-leak",
                "analysis-agent",
                "external_llm_context",
            ),
            sink="external_llm_context",
            redaction_applied=False,
            approval_scope="internal_validator",
            public_safe_summary="Canary signal is sent as context to an external model.",
        ),
        SinkAttempt(
            name="debug_trace_unredacted_signal",
            asset=asset,
            envelope=_signal_envelope("debug-trace-leak", "debug_logger", "debug_trace"),
            sink="debug_trace",
            redaction_applied=False,
            approval_scope="internal_validator",
            public_safe_summary="Canary signal enters debug trace with private fields intact.",
        ),
        SinkAttempt(
            name="memory_persistence_signal",
            asset=asset,
            envelope=_signal_envelope("memory-persistence-leak", "agent_memory", "agent_memory"),
            sink="agent_memory",
            redaction_applied=False,
            approval_scope="internal_validator",
            public_safe_summary="Canary signal is written to agent memory.",
        ),
        SinkAttempt(
            name="training_export_redacted_signal",
            asset=asset,
            envelope=_signal_envelope("training-redacted", "training_export", "training_export"),
            sink="training_export",
            redaction_applied=True,
            approval_scope="training_export",
            public_safe_summary="Redacted canary metadata moves into training export.",
        ),
        SinkAttempt(
            name="git_issue_handoff_signal",
            asset=asset,
            envelope=_signal_envelope("git-issue-leak", "handoff-agent", "git_issue_or_pr"),
            sink="git_issue_or_pr",
            redaction_applied=False,
            approval_scope="handoff_file",
            public_safe_summary="Canary signal is included in a GitHub issue or PR handoff.",
        ),
    ]


def trading_signal_canary() -> ProtectedAsset:
    """Return a safe stand-in for a private trading signal."""

    return ProtectedAsset(
        asset_id="PRIVATE_TRADING_SIGNAL_CANARY",
        asset_type="trading_signal",
        sensitivity="restricted",
        label="Validated paper trading signal canary",
        allowed_sinks=(
            "internal_validator",
            "paper_executor",
            "private_subscriber_channel",
            "training_export",
        ),
        forbidden_sinks=(
            "public_report",
            "external_llm_context",
            "git_issue_or_pr",
            "telemetry",
        ),
        redaction_required=True,
        redacted_fields=("symbol", "direction", "entry", "stop", "target", "reasoning"),
        canary_id="trading_signal_canary_001",
        content_hash="sha256:canary-redacted-example",
    )


def _signal_envelope(envelope_id: str, consumer: str, sink: SinkType) -> TransferEnvelope:
    consumed_as = "evidence"
    if sink in {"agent_memory", "external_llm_context", "git_issue_or_pr"}:
        consumed_as = "memory"
    if sink == "public_report":
        consumed_as = "data"
    return TransferEnvelope(
        envelope_id=envelope_id,
        producer="main_paper_bridge",
        consumer=consumer,
        payload_kind="strategy_card",
        trust_level="user_confirmed",
        authority_scope="read",
        payload={
            "asset_ref": "PRIVATE_TRADING_SIGNAL_CANARY",
            "fields": ["symbol", "direction", "entry", "stop", "target"],
            "sink": sink,
        },
        provenance=[
            ProvenanceStep(
                actor="validator",
                action="validated_canary_strategy",
                source="synthetic_setup_library",
            )
        ],
        consumed_as=consumed_as,  # type: ignore[arg-type]
        allowed_uses=["read"],
        approval_id="paper-signal-routing",
        approval_binding="private_subscriber_channel",
        created_at="2026-07-04T00:00:00Z",
        expires_at="2026-07-04T01:00:00Z",
    )


def _sink_policy_dimension(attempt: SinkAttempt, findings: list[Finding]) -> float:
    if attempt.sink in attempt.asset.forbidden_sinks:
        findings.append(
            _finding(
                "private_asset_forbidden_sink",
                "high",
                "Protected asset is routed to an explicitly forbidden sink.",
            )
        )
        return 1.0
    if attempt.sink not in attempt.asset.allowed_sinks and attempt.asset.sensitivity != "public":
        findings.append(
            _finding(
                "private_asset_unauthorized_sink",
                "high",
                "Protected asset is routed to a sink not listed as allowed.",
            )
        )
        return 0.85
    if attempt.approval_scope and attempt.approval_scope != attempt.sink:
        findings.append(
            _finding(
                "sink_approval_scope_mismatch",
                "medium",
                "Approval scope does not match the attempted sink.",
            )
        )
        return 0.45
    return 0.0


def _redaction_dimension(attempt: SinkAttempt, findings: list[Finding]) -> float:
    if not attempt.asset.redaction_required:
        return 0.0
    if attempt.sink in {"private_subscriber_channel", "paper_executor", "internal_validator"}:
        return 0.0
    if not attempt.redaction_applied:
        findings.append(
            _finding(
                "private_asset_unredacted",
                "high",
                "Protected asset reached a non-private sink without required redaction.",
            )
        )
        return 1.0
    return 0.0


def _persistence_dimension(attempt: SinkAttempt, findings: list[Finding]) -> float:
    if attempt.sink not in PERSISTENT_SINKS:
        return 0.0
    if attempt.sink == "training_export" and attempt.redaction_applied:
        return 0.0
    if attempt.asset.sensitivity in HIGH_SENSITIVITY and not attempt.redaction_applied:
        findings.append(
            _finding(
                "persistent_context_leak",
                "high",
                "Sensitive asset persists in memory, trace, handoff, or training context.",
            )
        )
        return 0.90
    return 0.20 if attempt.asset.sensitivity in HIGH_SENSITIVITY else 0.0


def _external_exposure_dimension(attempt: SinkAttempt, findings: list[Finding]) -> float:
    if attempt.sink not in PUBLIC_SINKS:
        return 0.0
    if attempt.asset.sensitivity in HIGH_SENSITIVITY:
        findings.append(
            _finding(
                "external_context_leak",
                "high",
                "Sensitive asset reached a public, external, or telemetry-like sink.",
            )
        )
        return 1.0
    return 0.35


def _role_confusion_dimension(attempt: SinkAttempt, findings: list[Finding]) -> float:
    if attempt.envelope.consumed_as in {"instruction", "policy", "capability_grant"}:
        findings.append(
            _finding(
                "private_asset_role_confusion",
                "high",
                "Protected asset is consumed as instruction, policy, or capability.",
            )
        )
        return 0.85
    if (
        attempt.sink in {"public_report", "git_issue_or_pr"}
        and attempt.envelope.consumed_as == "data"
    ):
        findings.append(
            _finding(
                "private_asset_public_content_confusion",
                "medium",
                "Protected asset is treated as publishable report content.",
            )
        )
        return 0.50
    return 0.0


def _traceability_dimension(attempt: SinkAttempt, findings: list[Finding]) -> float:
    if not attempt.envelope.provenance:
        findings.append(
            _finding(
                "private_asset_missing_provenance",
                "high",
                "Protected asset transfer lacks provenance.",
            )
        )
        return 1.0
    if not attempt.asset.canary_id and not attempt.asset.content_hash:
        findings.append(
            _finding(
                "private_asset_missing_canary",
                "medium",
                "Protected asset has no canary id or content hash for leak attribution.",
            )
        )
        return 0.45
    return 0.0


def _risk_level(score: float) -> RiskLevel:
    if score >= 0.68:
        return "high"
    if score >= 0.35:
        return "medium"
    if score >= 0.02:
        return "low"
    return "none"


def _finding(code: str, severity: str, message: str) -> Finding:
    if severity not in {"low", "medium", "high"}:
        raise ValueError(f"invalid severity: {severity}")
    return Finding(code=code, severity=severity, message=message)  # type: ignore[arg-type]
