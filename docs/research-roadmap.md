# Research Roadmap

This document tracks longer-horizon research questions for agentic transfer
verification. The project is defensive: it models how agent systems preserve
authority, provenance, and safety boundaries when data moves between tools,
memories, agents, runtimes, and ecosystems.

## R1: Cross-Ecosystem Transfer Integrity

Question: when one agent ecosystem passes data to another, how can the receiver
know what is instruction, what is evidence, what is memory, and what authority
actually travelled with the payload?

Why it matters:

- Agent handoffs often collapse task text, tool output, memory, and user intent
  into one prompt-like blob.
- Different vendors and runtimes do not share a universal trust envelope.
- A receiver may treat an untrusted quote, OCR transcript, tool output, or
  previous conversation as a current instruction.

Research direction:

- Define a minimal transfer envelope with explicit fields for source, trust,
  allowed use, authority, expiry, and audit references.
- Verify that receivers do not upgrade data into policy.
- Verify that memory and tool output cannot silently become instructions.
- Compare unsigned, hashed, and signed envelope variants.

Candidate checks:

- Missing provenance is rejected or downgraded.
- Untrusted content is usable as data only.
- Authority does not increase during transfer.
- Expired or stale memory cannot modify current policy.
- Audit chain records why the receiver accepted or downgraded a field.

## R2: Long-Horizon Semantic Drift Of Refusal Boundaries

Question: can a system slowly lose the operational meaning of a refusal boundary
over repeated interactions, memory writes, summaries, or agent handoffs?

The issue is not that a model forgets a word. The issue is that the runtime may
gradually reinterpret a refusal as negotiable, deferrable, transferable, or
overridable by context.

Expected failure shape:

- A refusal becomes a negotiation.
- "Do not execute" becomes "describe a plan".
- Old memory becomes current policy.
- A handoff from another agent is treated as authority.
- Logs record justification instead of real control evidence.
- The system still sounds safe while its boundary enforcement has degraded.

Research direction:

- Build multi-step scenarios that span several turns or runs.
- Track whether the same boundary is preserved across summaries, memories,
  tool outputs, and handoffs.
- Measure whether the system keeps the hierarchy of authority stable.
- Flag cases where a later step weakens an earlier refusal.

Candidate checks:

- Refusal meaning remains stable across repeated turns.
- Memory cannot rewrite policy.
- A later agent cannot reinterpret a prior refusal as permission.
- Audit records the original boundary and the source of any later decision.
- The system distinguishes explanation, planning, and execution.

## R3: Perception Boundary Verification

Question: can transcripts from OCR, ASR, screenshots, documents, browser pages,
or other perception tools stay classified as evidence instead of instructions?

Research direction:

- Model each perception output as untrusted evidence by default.
- Require a receiver to preserve channel labels.
- Check that OCR/ASR/document text cannot modify tool policy, memory policy, or
  user intent.

Candidate checks:

- OCR text is described or summarized, not followed as instruction.
- Audio transcripts are treated as content, not authority.
- Browser/page text cannot override runtime policy.
- A perception transcript that requests memory/tool changes is downgraded.

## R4: Ambient Authority And Capability Binding

Question: when an agent can access files, tools, shell, network, or memory, are
those capabilities tied to a specific authorized task, or are they ambient?

Research direction:

- Verify that capability grants are explicit, scoped, and time-limited.
- Check that a transfer envelope cannot silently add tool access.
- Check that stale memory cannot request elevated capabilities.

Candidate checks:

- Tool use requires explicit authority.
- Read-only tasks do not gain write access.
- Handoff payloads cannot add capabilities.
- Audit records the capability source.

## R5: Tamper-Evident Audit Trail

Question: can a user or reviewer reconstruct why an agent accepted, downgraded,
or rejected a transferred field?

Research direction:

- Define a compact audit event format.
- Optionally hash-link audit events.
- Verify that findings include evidence paths, not just final labels.

Candidate checks:

- Every transfer decision has a reason.
- Suppression labels do not remove audit records.
- Reports show source, trust level, decision, and control family.

## Product Milestones

### v0.2

- JSON loader and CLI.
- Report artifacts.
- More transfer scenarios: tool output, memory write, approval, OCR transcript.

### v0.3

- Cross-ecosystem transfer examples.
- Compatibility notes with `ai-agent-handoff`.
- Audit-chain checks.
- First long-horizon semantic drift scenario.

### v0.4

- Multi-step transfer replay.
- Memory provenance checks.
- Perception boundary checks.
- Run-to-run diff for authority changes.

### Later

- Optional signature/hash support.
- Adapter examples for common agent runtimes.
- Integration notes for `agentic-security-harness`.
- Comparative reports across local and hosted runtimes.
