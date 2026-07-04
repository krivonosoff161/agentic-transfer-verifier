from agentic_transfer_verifier import (
    ProtectedAsset,
    SinkAttempt,
    assess_sink_attempt,
    leakage_scenario_corpus,
    trading_signal_canary,
)
from agentic_transfer_verifier.asset_leakage import _signal_envelope


def test_trading_signal_canary_declares_allowed_and_forbidden_sinks() -> None:
    asset = trading_signal_canary()

    assert asset.asset_id == "PRIVATE_TRADING_SIGNAL_CANARY"
    assert asset.sensitivity == "restricted"
    assert "private_subscriber_channel" in asset.allowed_sinks
    assert "public_report" in asset.forbidden_sinks
    assert "external_llm_context" in asset.forbidden_sinks
    assert asset.redaction_required is True
    assert "entry" in asset.redacted_fields


def test_allowed_private_subscriber_signal_is_not_a_leak() -> None:
    attempt = next(
        item
        for item in leakage_scenario_corpus()
        if item.name == "allowed_private_subscriber_signal"
    )
    assessment = assess_sink_attempt(attempt)

    assert assessment.level == "none"
    assert assessment.findings == ()
    assert assessment.dimensions["sink_policy"] == 0.0
    assert assessment.dimensions["redaction"] == 0.0


def test_public_report_unredacted_signal_is_high_risk() -> None:
    attempt = next(
        item for item in leakage_scenario_corpus() if item.name == "public_report_unredacted_signal"
    )
    assessment = assess_sink_attempt(attempt)
    codes = {finding.code for finding in assessment.findings}

    assert assessment.level == "high"
    assert "private_asset_forbidden_sink" in codes
    assert "private_asset_unredacted" in codes
    assert "external_context_leak" in codes
    assert "private_asset_public_content_confusion" in codes


def test_external_llm_context_signal_is_high_risk() -> None:
    attempt = next(
        item for item in leakage_scenario_corpus() if item.name == "external_llm_context_signal"
    )
    assessment = assess_sink_attempt(attempt)
    codes = {finding.code for finding in assessment.findings}

    assert assessment.level == "high"
    assert "external_context_leak" in codes
    assert "private_asset_forbidden_sink" in codes
    assert "private_asset_unredacted" in codes


def test_persistent_memory_signal_is_detected_without_public_sink() -> None:
    attempt = next(
        item for item in leakage_scenario_corpus() if item.name == "memory_persistence_signal"
    )
    assessment = assess_sink_attempt(attempt)
    codes = {finding.code for finding in assessment.findings}

    assert assessment.level == "medium"
    assert "persistent_context_leak" in codes
    assert "private_asset_unauthorized_sink" in codes
    assert "external_context_leak" not in codes


def test_redacted_training_export_is_allowed() -> None:
    attempt = next(
        item for item in leakage_scenario_corpus() if item.name == "training_export_redacted_signal"
    )
    assessment = assess_sink_attempt(attempt)

    assert assessment.level == "none"
    assert assessment.findings == ()


def test_custom_internal_asset_can_allow_memory_when_redacted() -> None:
    asset = ProtectedAsset(
        asset_id="INTERNAL_AUDIT_TRACE_CANARY",
        asset_type="audit_trace",
        sensitivity="confidential",
        label="Internal audit trace canary",
        allowed_sinks=("agent_memory",),
        redaction_required=True,
        redacted_fields=("raw_prompt", "raw_response"),
        canary_id="audit_trace_canary_001",
    )
    attempt = SinkAttempt(
        name="redacted_audit_memory",
        asset=asset,
        envelope=_signal_envelope("redacted-audit-memory", "agent_memory", "agent_memory"),
        sink="agent_memory",
        redaction_applied=True,
        approval_scope="agent_memory",
    )

    assessment = assess_sink_attempt(attempt)

    assert assessment.level == "low"
    assert assessment.dimensions["persistence"] == 0.2


def test_leakage_corpus_has_expected_cases() -> None:
    assert {case.name for case in leakage_scenario_corpus()} == {
        "allowed_private_subscriber_signal",
        "public_report_unredacted_signal",
        "external_llm_context_signal",
        "debug_trace_unredacted_signal",
        "memory_persistence_signal",
        "training_export_redacted_signal",
        "git_issue_handoff_signal",
    }
