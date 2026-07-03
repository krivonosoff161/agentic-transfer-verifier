from agentic_transfer_verifier import (
    assess_attack_chain,
    attack_chain_corpus,
    detection_signal_catalog,
)


def test_detection_signal_catalog_covers_core_boundary_failures() -> None:
    catalog = detection_signal_catalog()

    assert "data_consumed_as_instruction" in catalog
    assert catalog["data_consumed_as_instruction"].phase == "role_confusion"
    assert "unauthorized_trust_promotion" in catalog
    assert catalog["unauthorized_trust_promotion"].phase == "trust_promotion"
    assert "capability_exceeds_authority" in catalog
    assert catalog["capability_exceeds_authority"].phase == "authority_or_capability_gain"
    assert "profile_missing_provenance" in catalog
    assert catalog["profile_missing_provenance"].phase == "evidence_degradation"


def test_attack_chain_corpus_has_expected_cases() -> None:
    chains = attack_chain_corpus()

    assert {chain.name for chain in chains} == {
        "repo_text_to_tool_write",
        "tool_metadata_to_capability",
        "memory_replay_to_policy",
        "approval_reuse_to_action",
        "delegated_agent_identity_drift",
        "audit_gap_after_summary",
    }
    assert all(chain.public_safe_summary for chain in chains)
    assert all(len(chain.envelopes) == len(chain.parent_map) for chain in chains)


def test_attack_chain_assessment_detects_expected_signals() -> None:
    for chain in attack_chain_corpus():
        assessment = assess_attack_chain(chain)

        assert assessment.missing_expected_signals == ()
        assert set(chain.expected_signals) <= set(assessment.observed_signals)
        assert assessment.level in {"medium", "high"}
        assert assessment.covered_phases
        assert assessment.findings


def test_repo_text_chain_models_role_confusion_and_authority_gain() -> None:
    chain = next(item for item in attack_chain_corpus() if item.name == "repo_text_to_tool_write")
    assessment = assess_attack_chain(chain)

    assert assessment.level == "high"
    assert "role_confusion" in assessment.covered_phases
    assert "authority_or_capability_gain" in assessment.covered_phases
    assert "data_consumed_as_instruction" in assessment.observed_signals
    assert "weak_trust_authority" in assessment.observed_signals


def test_audit_gap_chain_remains_detectable_without_action_payload() -> None:
    chain = next(item for item in attack_chain_corpus() if item.name == "audit_gap_after_summary")
    assessment = assess_attack_chain(chain)

    assert assessment.level == "medium"
    assert "profile_missing_provenance" in assessment.observed_signals
    assert "parent_mismatch" in assessment.observed_signals
    assert "authority_escalation" not in assessment.observed_signals
