# Trust/Risk Model

This document defines the first public research model behind
`assess_transfer_risk(...)`.

The model answers a narrow question:

> Given one declared transfer envelope, which structural weaknesses make it
> risky for a receiving agent to trust?

It does not answer whether a real identity is authentic, whether a signature is
valid, whether the model will obey policy, or whether a production system is
safe.

## Source Baseline

The model is source-backed vocabulary, not a compliance claim:

- W3C PROV gives a general model for entities, activities, agents, and
  provenance relations:
  <https://www.w3.org/TR/prov-overview/>
  and <https://www.w3.org/TR/prov-dm/>
- in-toto and SLSA show how supply-chain systems bind provenance and
  attestations to artifacts:
  <https://github.com/in-toto/attestation>
  and <https://slsa.dev/spec/v0.1/provenance>
- OpenAI handoffs and guardrails describe explicit agent transitions and
  boundary checks:
  <https://openai.github.io/openai-agents-python/handoffs/>
  and <https://openai.github.io/openai-agents-python/guardrails/>
- OpenAI agent safety guidance emphasizes bounded, observable agent actions:
  <https://developers.openai.com/api/docs/guides/agent-builder-safety>
- Model Context Protocol security guidance treats tools, prompts, and servers as
  security boundaries:
  <https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices>
- OWASP Top 10 for LLM Applications names risks such as prompt injection,
  sensitive information disclosure, supply-chain risk, and excessive agency:
  <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- NIST AI RMF Generative AI Profile frames measurement and monitoring as ongoing
  risk management:
  <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>

## Envelope Variables

One transfer is modeled as:

```text
T = (producer, consumer, payload, provenance, trust, authority, approval, time, audit)
```

Where:

- `producer` and `consumer` identify the declared endpoints;
- `payload` is the content being transferred;
- `provenance` is the declared chain of actors/actions/sources;
- `trust` is one of `untrusted`, `user_confirmed`, `tool_observed`, `verified`;
- `authority` is one of `none`, `read`, `write`, `execute`, `admin`;
- `approval` is `approval_id` plus `approval_binding`;
- `time` is `created_at` plus `expires_at`;
- `audit` is the structural reviewability of ids, endpoints, payload kind, and
  parent linkage.

## Component Scores

Each component is bounded to `[0, 1]`:

| Component | Meaning |
|---|---|
| `provenance_integrity` | Missing provenance or incomplete actor/action/source fields. |
| `authority_movement` | Authority attached to data whose trust level is too weak. |
| `approval_binding` | Approval missing or not bound to the exact action/payload. |
| `freshness` | Expiry/creation gaps around replay-sensitive or authority-bearing data. |
| `auditability` | Missing ids/endpoints/payload kind/payload, self-parenting, or same endpoint ambiguity. |

The score uses a bounded weighted sum:

```text
risk(T) = min(1.0,
    0.25 * provenance_integrity
  + 0.25 * authority_movement
  + 0.20 * approval_binding
  + 0.15 * freshness
  + 0.15 * auditability
)
```

Risk levels:

| Score | Level |
|---:|---|
| `0.0` | `none` |
| `0.0 < score < 0.35` | `low` |
| `0.35 <= score < 0.70` | `medium` |
| `0.70 <= score <= 1.0` | `high` |

The weights are intentionally simple and inspectable. They are not empirical
probabilities.

## Why These Components

**Provenance integrity** is first because a receiver needs to know what produced
the payload and through which transformations it moved.

**Authority movement** is high weight because agent failures often happen when
data silently becomes instruction, permission, or tool capability.

**Approval binding** checks whether permission remains attached to a specific
action or payload instead of becoming ambient authority.

**Freshness** captures stale context and replay risk. A valid old handoff can be
unsafe as current authority.

**Auditability** captures whether a reviewer can reconstruct why the consumer
accepted, downgraded, or rejected a transfer.

## Example

```python
from agentic_transfer_verifier import assess_transfer_risk

risk = assess_transfer_risk(envelope)
print(risk.to_dict())
```

Example output:

```python
{
    "model_version": "0.1",
    "envelope_id": "env-1",
    "score": 0.353,
    "level": "medium",
    "components": {
        "provenance_integrity": 0.0,
        "authority_movement": 0.9,
        "approval_binding": 0.45,
        "freshness": 0.25,
        "auditability": 0.0,
    },
}
```

Interpretation: the payload may have clean provenance and audit fields, but
`untrusted` data with `write` authority and no approval binding is still risky.

## Relationship To `verify_envelope`

`verify_envelope(...)` returns deterministic findings and a coarse status:
`PASS`, `WARN`, or `FAIL`.

`assess_transfer_risk(...)` returns a structural score and component breakdown.

They answer different questions:

- verifier status: "Which invariant failed?"
- risk score: "Which weak assumptions make this transfer risky?"

The two should be read together. A transfer can pass basic structure while still
deserving a non-zero risk score in a stricter deployment profile.

## Weak Points

Known limits of this first model:

- It does not authenticate identities.
- It does not validate signatures, hashes, or external attestations.
- It does not parse natural-language payload intent.
- It does not know whether a real user approved an action.
- It does not compare timestamps semantically; it only checks structural gaps.
- It does not model multi-step collusion or delayed agent behavior.
- The weights are hand-authored and need calibration against scenario corpora.
- It can under-score a well-formed but malicious envelope.

## Research Next

The next research steps are:

- scenario corpus for tool output, memory write, approval, OCR transcript, and
  cross-runtime summary transfers;
- calibration of component weights against synthetic failure cases;
- optional hash/signature binding for payload and approval fields;
- report artifacts that include verifier findings and risk components;
- integration with `agentic-security-harness` traces for replayable evidence.
