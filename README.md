# Agentic Transfer Verifier

Research toolkit for validating data, context, provenance, and authority
handoffs between heterogeneous AI agent runtimes.

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
- Did an approval remain bound to the exact action it approved?
- Did authority travel with data accidentally?
- Is the context stale or replayed?
- Is the audit trail complete enough to review?

## What This Is Not

- Not a universal standard.
- Not a vendor certification.
- Not a sandbox.
- Not a live exploit tool.
- Not a replacement for access control, identity, or cryptographic protocols.

The first release is deliberately small and local. It uses synthetic examples
and deterministic checks only.

## Relationship To Other Projects

- [agentic-security-harness](https://github.com/krivonosoff161/agentic-security-harness)
  measures agentic failure modes with traces and scorecards.
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

## Current Status

Pre-release research skeleton:

- local Python package;
- structured transfer envelope;
- deterministic verifier;
- tests;
- docs for the problem and boundary model.

No network calls. No provider credentials. No real target integrations.

## Docs

- [Problem statement](docs/problem-statement.md)
- [Boundary model](docs/boundary-model.md)
- [Data envelope](docs/data-envelope.md)
- [Roadmap](docs/roadmap.md)

## License

MIT. Research and education only.
