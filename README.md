# Agentic Transfer Verifier

Research toolkit for validating data, context, provenance, trust, and authority
handoffs between heterogeneous AI agent runtimes.

This repository is part of the **Agentic AI Security core**:

```text
playbooks make boundaries explicit
-> handoff files move work between agents
-> transfer verifier checks provenance, trust, and authority
-> security harness measures boundary failures with evidence
```

Agent systems increasingly pass information through files, tool output, memory,
browser/OCR/audio transcripts, IDE state, and summaries written by another
model. Those transfers are often plain text. Plain text is easy to move, but it
does not say enough about origin, freshness, trust level, or authority.

This project explores a safer pattern:

```text
agent/runtime output -> structured envelope -> verification checks -> handoff report
```

## What This Checks

- Did the payload keep its declared source and provenance chain?
- Did trust level increase without an explicit verifier?
- Did an agent handoff promote trust or authority across a parent -> child edge?
- Did an approval remain bound to the exact action it approved?
- Did authority travel with data accidentally?
- Did tool output, memory, or an Agent Card become instruction or capability?
- Is the context stale or replayed?
- Is the audit trail complete enough to review?
- Which structural risk components explain the transfer's risk score?

## What This Is Not

- Not a universal standard.
- Not a vendor certification.
- Not a sandbox.
- Not a live exploit tool.
- Not a replacement for access control, identity, or cryptographic protocols.

The current research release is deliberately small and local. It uses synthetic
examples and deterministic checks only.

## Relationship To Other Projects

- [agentic-security-harness](https://github.com/krivonosoff161/agentic-security-harness)
  measures agentic failure modes with traces and scorecards.
- [llm-safety-playbooks](https://github.com/krivonosoff161/llm-safety-playbooks)
  gives lightweight task-brief rules for making LLM and agent boundaries
  explicit before deeper verification is available.
- [ai-agent-handoff](https://github.com/krivonosoff161/ai-agent-handoff)
  provides a practical file-based handoff protocol for coding agents.
- `agentic-transfer-verifier` focuses on validating the handoff data itself:
  envelope, provenance, trust level, authority, freshness, and auditability.

## Install

```bash
git clone https://github.com/krivonosoff161/agentic-transfer-verifier
cd agentic-transfer-verifier
pip install -e .
python -m pytest -q
```

## Minimal Example

```python
from agentic_transfer_verifier import (
    TransferEnvelope,
    ProvenanceStep,
    verify_envelope,
)

envelope = TransferEnvelope(
    envelope_id="demo-1",
    producer="agent-a",
    consumer="agent-b",
    payload_kind="summary",
    trust_level="untrusted",
    authority_scope="none",
    payload={"summary": "User asked for a docs review."},
    provenance=[
        ProvenanceStep(actor="user", action="created", source="chat"),
        ProvenanceStep(actor="agent-a", action="summarized", source="TASK.md"),
    ],
)

report = verify_envelope(envelope)
print(report.status)       # PASS
print(report.findings)     # []
```

## Risk Model Example

```python
from agentic_transfer_verifier import assess_transfer_risk

risk = assess_transfer_risk(envelope)
print(risk.score)       # 0.0
print(risk.components)  # provenance, authority, approval, freshness, auditability
```

The risk score is deterministic and structural. It is not a probability, not a
certification result, and not a replacement for identity, signatures, runtime
isolation, or policy enforcement. See [Trust/risk model](docs/trust-risk-model.md).

## Formal Transfer Profile v0.2

v0.2 adds a multi-dimensional profile for parent -> child agent transfers:

```python
from agentic_transfer_verifier import assess_transfer_profile, scenario_corpus

for scenario in scenario_corpus():
    profile = assess_transfer_profile(scenario.envelope, parent=scenario.parent)
    print(scenario.name, profile.level, profile.to_dict()["score"])
```

Built-in scenarios currently cover:

- clean handoff;
- unverified trust promotion;
- tool output consumed as instruction;
- approval laundering;
- Agent Card capability drift;
- replayed memory consumed as policy;
- missing provenance audit gap.

See [Formal transfer model v0.2](docs/formal-transfer-model-v02.md).

## Current Status

Research v0.2:

- local Python package;
- structured transfer envelope;
- deterministic verifier;
- deterministic transfer risk assessment;
- formal transfer profile for trust, identity, authority, capability, replay,
  instruction-boundary, and audit dimensions;
- synthetic v0.2 scenario corpus;
- tests;
- docs for the problem and boundary model.

No network calls. No provider credentials. No real target integrations.

## Docs

- [Problem statement](docs/problem-statement.md)
- [Boundary model](docs/boundary-model.md)
- [Data envelope](docs/data-envelope.md)
- [Trust/risk model](docs/trust-risk-model.md)
- [Formal transfer model v0.2](docs/formal-transfer-model-v02.md)
- [Roadmap](docs/roadmap.md)

## License

MIT. Research and education only.
