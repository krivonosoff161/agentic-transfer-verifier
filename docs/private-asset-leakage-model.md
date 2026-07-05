# Private Asset Leakage Model

Portfolio-level public/private rules are defined in the
[Documentation Contract](https://github.com/krivonosoff161/krivonosoff161/blob/main/docs/documentation-contract.md).
This model narrows that rule for private-asset movement through agentic
workflows.

This document defines the private-asset leakage model behind
`assess_sink_attempt(...)`.

The motivating example is a validated trading signal or strategy card moving
through an agentic workflow. The public repository never contains a real signal.
It uses `PRIVATE_TRADING_SIGNAL_CANARY`, a synthetic stand-in with the same
security shape:

```text
validated private asset -> transfer envelope -> consumer -> output sink
```

The research question is:

> When an agentic workflow handles a private asset, how can the asset leak
> through the wrong sink, missing redaction, memory persistence, debug traces,
> public reports, external model context, or approval/sink confusion?

## Local Reference Boundary

This model was shaped by a read-only review of a local trading-bot architecture.
No `.env`, credentials, Telegram channels, private strategy artifacts, provider
API calls, or live systems were read or used.

The relevant local structure is abstracted as:

```text
validator / PFR-ready rows
  -> main_paper_bridge
  -> main_paper_consumer
  -> main_paper_runtime_queue
  -> main_paper_runtime_observation
  -> main_paper_trade_ledger
  -> paper_telegram_preview
  -> paper_signal_training_export
```

The important security properties are:

- `execution_allowed=false`;
- Telegram preview is an output surface, not an executor;
- public reports and GitHub issues are not valid sinks for private signal
  fields;
- training exports may be allowed only when private fields are redacted;
- broad research rows must not silently become subscriber cards.

## Source Baseline

The model borrows defensive vocabulary from public sources:

| Source | Relevance |
|---|---|
| OWASP LLM Top 10 | Sensitive information disclosure, insecure output handling, excessive agency, and plugin/tool design risks. |
| OWASP Top 10 for Agentic Applications | Agentic systems plan, act, and make decisions across complex workflows, so sink control matters. |
| OWASP Agentic Skills Top 10 | The dangerous combination is private data, untrusted content, and external communication. |
| MCP Tools specification | Clients should show tool inputs before sensitive operations to avoid accidental or malicious data exfiltration. |
| MCP Authorization specification | Confused-deputy and token audience problems map to wrong-recipient and wrong-sink failures. |
| NIST AI 600-1 | Risk management should include governance, content provenance, testing, and incident disclosure. |
| MITRE ATLAS | Exfiltration should be modeled as an adversarial objective, not merely as bad output text. |

Primary references:

- <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- <https://owasp.org/www-project-agentic-skills-top-10/>
- <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- <https://atlas.mitre.org/>

## Asset And Sink Model

A protected asset is modeled as:

```text
A = (
    asset_id,
    asset_type,
    sensitivity,
    allowed_sinks,
    forbidden_sinks,
    redaction_required,
    redacted_fields,
    canary_id,
    content_hash
)
```

A sink attempt is:

```text
X = (
    asset,
    transfer_envelope,
    sink,
    redaction_applied,
    approval_scope
)
```

The verifier does not need the real asset value. It needs the asset label,
sensitivity, sink policy, and a canary/hash marker that lets a reviewer prove
whether the asset crossed a boundary.

## Trading Signal Canary

The built-in canary is:

```text
asset_id: PRIVATE_TRADING_SIGNAL_CANARY
asset_type: trading_signal
sensitivity: restricted
canary_id: trading_signal_canary_001
content_hash: sha256:canary-redacted-example
```

Allowed sinks:

- `internal_validator`
- `paper_executor`
- `private_subscriber_channel`
- `training_export`

Forbidden sinks:

- `public_report`
- `external_llm_context`
- `git_issue_or_pr`
- `telemetry`

Redacted fields:

- `symbol`
- `direction`
- `entry`
- `stop`
- `target`
- `reasoning`

The public corpus never contains real values for these fields.

## Leak Vectors

| Vector | Attempted confusion | Detection signal |
|---|---|---|
| Data-to-instruction | Private signal becomes a task or publication instruction. | `private_asset_role_confusion` |
| Memory leakage | Signal is written to agent memory. | `persistent_context_leak` |
| Tool output leakage | Validator/tool output is copied into a wider report. | `private_asset_unredacted` |
| Handoff leakage | Handoff file carries private fields to another agent. | `private_asset_unauthorized_sink` |
| Approval laundering | Approval for private delivery is reused for public output. | `sink_approval_scope_mismatch` |
| Sink confusion | Private Telegram/subscriber channel is treated like public report. | `private_asset_forbidden_sink` |
| Debug trace exposure | Debug/audit trace stores raw private fields. | `persistent_context_leak` |
| External LLM context leak | Signal is sent to an external model context. | `external_context_leak` |
| GitHub issue/PR leak | Private signal appears in public development artifacts. | `private_asset_forbidden_sink` |
| Capability escalation | Agent can read private asset and write public sink. | Existing authority/capability profile signals. |

## Detection Signals

| Signal | Meaning |
|---|---|
| `private_asset_forbidden_sink` | Asset is routed to an explicitly forbidden sink. |
| `private_asset_unauthorized_sink` | Sink is neither explicitly allowed nor public-safe. |
| `private_asset_unredacted` | Redaction was required but not applied before a non-private sink. |
| `persistent_context_leak` | Asset persists in memory, trace, handoff, or training context. |
| `external_context_leak` | Asset reaches public, external, telemetry, or model context. |
| `private_asset_role_confusion` | Asset is consumed as instruction, policy, or capability. |
| `private_asset_public_content_confusion` | Asset is treated as publishable report content. |
| `private_asset_missing_provenance` | Reviewer cannot reconstruct how the asset moved. |
| `private_asset_missing_canary` | Asset has no canary/hash marker for attribution. |
| `sink_approval_scope_mismatch` | Approval scope does not match attempted sink. |

## Scoring Model

The sink score is a bounded weighted sum:

```text
leakage_score(X) = min(1.0,
    0.30 * sink_policy
  + 0.22 * redaction
  + 0.14 * persistence
  + 0.16 * external_exposure
  + 0.10 * role_confusion
  + 0.08 * traceability
  + 0.10 * transfer_profile_score
)
```

Risk levels:

| Score | Level |
|---:|---|
| `< 0.02` | `none` |
| `0.02 <= score < 0.35` | `low` |
| `0.35 <= score < 0.68` | `medium` |
| `0.68 <= score <= 1.0` | `high` |

The weights are not empirical probabilities. They encode defensive priorities:
wrong sink and missing redaction matter most; persistence and external exposure
matter next; role confusion and traceability provide supporting evidence.

## Synthetic Corpus

`leakage_scenario_corpus()` includes:

| Scenario | Expected result |
|---|---|
| `allowed_private_subscriber_signal` | Allowed private sink; no leak. |
| `public_report_unredacted_signal` | High risk: forbidden public sink and no redaction. |
| `external_llm_context_signal` | High risk: restricted asset sent to external model context. |
| `debug_trace_unredacted_signal` | Medium risk: private fields persist in debug trace. |
| `memory_persistence_signal` | Medium risk: private fields persist in agent memory. |
| `training_export_redacted_signal` | Allowed when redacted. |
| `git_issue_handoff_signal` | High risk: public GitHub sink and persistent handoff exposure. |

Example:

```python
from agentic_transfer_verifier import assess_sink_attempt, leakage_scenario_corpus

for case in leakage_scenario_corpus():
    assessment = assess_sink_attempt(case)
    print(case.name, assessment.level, assessment.to_dict()["score"])
```

## Benign Counterexamples

The model intentionally allows:

- a validated signal moving to a private subscriber channel;
- redacted metadata moving into a training export;
- redacted audit traces moving into memory when memory is explicitly allowed;
- internal validator and paper executor handoff when scope matches.

Without benign cases, a verifier becomes a noisy scanner rather than a useful
control.

## False Positives

Expected false positives:

- A sink may be named `debug_trace` but stored in an encrypted internal vault.
- A training export may be private and short-lived, but the model treats it as
  persistent unless policy says otherwise.
- A public report may include a fully redacted canary marker for audit; the model
  needs `redaction_applied=true` to avoid over-alerting.
- Some subscriber channels are external systems but still business-approved
  sinks.

## False Negatives

Expected false negatives:

- A real signal can be paraphrased without matching canary markers.
- Redaction can be incomplete semantically even when the flag says it was
  applied.
- A malicious agent can split fields across several sinks.
- The model does not inspect screenshots, images, or rendered charts for hidden
  private fields.
- The model does not prove a recipient deleted or retained the asset.

## Public / Private Split

Public repository may include:

- canary asset structure;
- sink policy;
- abstract leak vectors;
- redacted example traces;
- deterministic tests.

Private research may include:

- real trading signal structure;
- raw strategy fields;
- private Telegram channel ids;
- provider-specific responses;
- local logs from working systems;
- exact attempts to trick a local agent into exporting a private signal.

## Relationship To Existing Models

The transfer profile asks:

> Is the handoff structurally risky?

The adversarial chain model asks:

> Which attack-chain phase does this support?

The asset leakage model asks:

> Did a protected asset move to a sink that policy, redaction, and approval do
> not allow?

Together:

```text
TransferEnvelope -> TransferRiskProfile -> AttackChainCase -> SinkAssessment
```

## Research Next

- Add JSON fixtures for sink policies.
- Add redacted trace export.
- Add split-leak scenarios where fields leak across several allowed-looking
  sinks.
- Add rendered artifact scanning for screenshots/charts/reports.
- Add private calibration notes using local-only trading-bot traces.
