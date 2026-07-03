# Formal Transfer Model v0.2

`assess_transfer_profile(...)` extends the original structural verifier into a
small formal model for agent-to-agent transfer risk.

For the deeper theoretical compromise and detection-chain model, see
[adversarial-transfer-detection-model.md](adversarial-transfer-detection-model.md).

The model is still local and deterministic. It does not contact providers,
authenticate real identities, validate cryptographic signatures, or claim that a
production agent is safe. Its job is narrower: make trust, provenance,
authority, and agent handoff assumptions explicit enough to test.

## Why v0.2 Exists

Agent systems increasingly exchange work through summaries, memory records, tool
output, Agent Cards, MCP resources, handoff files, and other plain-text
artifacts. A receiving agent can easily confuse:

- data with instruction;
- observation with permission;
- advertised capability with granted authority;
- old memory with current policy;
- another agent's summary with verified evidence.

v0.2 models that transfer as an edge:

```text
parent envelope -> child envelope
```

The edge records the trust and authority state before and after the handoff.
Risk is assigned when the child envelope upgrades trust, authority, capability,
or consumption mode without enough declared evidence.

## Source Baseline

The model borrows vocabulary from public defensive work. This is not a
compliance claim.

| Source family | How it informs this model |
|---|---|
| W3C PROV | Provenance is treated as an actor/action/source chain. |
| SLSA and in-toto | Attestations motivate binding claims to artifacts and build steps. |
| A2A Protocol | Agent Cards and opaque agent collaboration motivate discovery and capability checks. |
| AGNTCY identity | Verifiable agent identity, DIDs, credentials, and badges motivate identity claims. |
| IETF AI agent trust/security drafts | Registration, discovery, credential verification, and capability matching motivate trust transition checks. |
| NSA MCP Security Design Considerations | Capability drift, bearer-token/session risks, and tool invocation logging motivate freshness, replay, and audit checks. |
| NIST AI 600-1 | Provenance tracking, integrity, TEVV, and documented limitations motivate trace-first evaluation. |
| OWASP LLM Top 10 | Prompt injection, excessive agency, sensitive information exposure, and supply-chain risk motivate the boundary scenarios. |

Primary references:

- <https://www.w3.org/TR/prov-overview/>
- <https://slsa.dev/spec/v1.0/provenance>
- <https://github.com/in-toto/attestation>
- <https://github.com/a2aproject/A2A>
- <https://docs.agntcy.org/identity/identity/>
- <https://www.ietf.org/archive/id/draft-ni-a2a-ai-agent-security-requirements-01.html>
- <https://datatracker.ietf.org/doc/html/draft-yu-network-trust-framework-for-ai-agents-00>
- <https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF>
- <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

## Trust Lattice

v0.2 uses an ordered trust lattice:

```text
untrusted < tool_observed < user_confirmed < verified < signed < attested
```

Meaning:

| Trust level | Meaning in this project |
|---|---|
| `untrusted` | Data with no reliable source claim. |
| `tool_observed` | Output observed from a tool or runtime, but not endorsed as authority. |
| `user_confirmed` | User confirmed the content or task context. |
| `verified` | A verifier step declares the transfer checked. |
| `signed` | A declared signature-like binding exists. The current code does not validate it. |
| `attested` | A declared attestation-like binding exists. The current code does not validate it. |

Trust may stay the same or move downward without risk. Trust moving upward is
allowed only when the envelope declares both verifier provenance and verified
identity. Otherwise the model emits `unauthorized_trust_promotion`.

## Authority Lattice

Authority is also ordered:

```text
none < read < write < execute < admin
```

Authority risk appears when:

- authority increases across a parent -> child edge;
- weakly trusted content carries `write` or stronger authority;
- capability grants exceed the envelope authority;
- authority-bearing envelopes have no expiry or approval binding.

## Consumption Modes

The same payload can be safe or unsafe depending on how the receiver consumes it.

Allowed modes:

- `data`
- `evidence`
- `memory`
- `instruction`
- `policy`
- `capability_grant`

Data-like payloads such as `tool_output`, `memory`, `summary`, `ocr_transcript`,
`asr_transcript`, `browser_page`, and `agent_card` are risky when consumed as
instruction, policy, or capability grant.

## Risk Dimensions

The profile score is a bounded weighted sum:

```text
profile(T) = min(1.0,
    0.15 * provenance
  + 0.12 * identity
  + 0.14 * trust_transition
  + 0.15 * authority_transition
  + 0.12 * capability_binding
  + 0.10 * freshness_replay
  + 0.12 * instruction_boundary
  + 0.10 * auditability
)
```

Risk levels:

| Score | Level |
|---:|---|
| `0.0` | `none` |
| `0.0 < score < 0.20` | `low` |
| `0.20 <= score < 0.55` | `medium` |
| `0.55 <= score <= 1.0` | `high` |

The weights are hand-authored for inspectability. They are not empirical
probabilities.

## Built-In Scenario Corpus

`scenario_corpus()` currently includes seven synthetic cases:

| Scenario | Expected level | Main signal |
|---|---|---|
| `clean_handoff` | `none` | Proper parent link, identity, provenance, and read-only evidence. |
| `unverified_trust_promotion` | `medium` | Child claims `verified` without verifier provenance and verified identity. |
| `tool_output_as_instruction` | `medium` | Tool output is consumed as instruction with write authority. |
| `approval_laundering` | `medium` | Approval binding does not match the action declared in payload. |
| `agent_card_capability_drift` | `medium` | Agent card grants write capability without verified identity or binding. |
| `self_replay_memory_policy` | `medium` | Memory envelope replays itself as parent and is consumed as policy. |
| `audit_gap` | `low` | Missing provenance, but no authority movement. |

Example:

```python
from agentic_transfer_verifier import assess_transfer_profile, scenario_corpus

for scenario in scenario_corpus():
    profile = assess_transfer_profile(scenario.envelope, parent=scenario.parent)
    print(scenario.name, profile.level, profile.score)
```

## Example Output Shape

```python
{
    "model_version": "0.2",
    "envelope_id": "tool-output-instruction",
    "score": 0.281,
    "level": "medium",
    "dimensions": {
        "provenance": 0.0,
        "identity": 0.0,
        "trust_transition": 0.0,
        "authority_transition": 0.85,
        "capability_binding": 0.0,
        "freshness_replay": 0.45,
        "instruction_boundary": 0.9,
        "auditability": 0.0,
    },
    "violations": [
        {"code": "authority_escalation", "severity": "high"},
        {"code": "weak_trust_authority", "severity": "high"},
        {"code": "data_consumed_as_instruction", "severity": "high"},
    ],
}
```

## Current Limits

- Identity claims are declared fields; the verifier does not resolve DIDs,
  verify credentials, or check signatures.
- `signed` and `attested` are trust levels, not cryptographic validation.
- Payload intent is not semantically parsed.
- The scenario corpus is synthetic.
- The weights are not calibrated against production incidents.
- The model does not test live providers, hosted agents, or real enterprise
  systems.
- The model can miss a well-formed malicious transfer.

## Research Next

- Add hash/signature verification adapters behind explicit optional interfaces.
- Expand benign counterexamples for false-positive calibration.
- Add JSON fixtures for scenario replay.
- Add report artifacts that combine verifier findings and v0.2 profile
  dimensions.
- Compare local synthetic profile results with `agentic-security-harness` traces.
