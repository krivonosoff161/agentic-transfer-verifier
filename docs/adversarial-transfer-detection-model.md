# Adversarial Transfer Detection Model

This document defines the deeper research model behind
`assess_attack_chain(...)`.

The core question is:

> How can an agentic system be compromised through transfers of data, memory,
> tool output, metadata, approval, or delegated work, and what evidence can a
> verifier collect before the failure becomes invisible?

The answer is not "scan prompts for bad words." In agentic systems the dangerous
failure is usually a role and authority transition:

```text
untrusted material -> accepted context -> trusted summary -> authority-bearing action
```

The verifier therefore treats compromise as a chain of state transitions, not as
a single malicious string.

## Defensive Scope

This model is defensive and synthetic.

It does:

- model how boundary failures propagate;
- identify evidence that a reviewer can inspect;
- define abstract detection signals;
- provide safe synthetic chain cases;
- connect transfer verification to public security frameworks.

It does not:

- provide exploit payload recipes;
- test real providers;
- bypass hosted model safeguards;
- target live systems;
- claim certification or complete protection.

## Source Baseline

The model is grounded in public defensive sources:

| Source | Relevant point for this model |
|---|---|
| OWASP Top 10 for Agentic Applications 2026 | Agentic risk is about systems that plan, act, and decide across workflows. |
| OWASP AIUC-1 crosswalk | Agentic risks include goal hijacking, tool misuse, identity/privilege abuse, memory poisoning, insecure inter-agent communication, cascading failures, trust exploitation, and rogue agents. |
| OWASP LLM Top 10 | Prompt injection, insecure output handling, plugin design, excessive agency, and sensitive information disclosure map to transfer failures. |
| OWASP Agentic Skills Top 10 | Skills are the execution layer; installed skills need publisher verification, permissions, isolation, monitoring, and audit logging. |
| MCP specification | Tools are model-controlled; human review, clear tool visibility, and confirmation prompts are recommended for trust and safety. |
| MCP authorization specification | Authorization is optional, STDIO credentials may come from environment, and confused-deputy/token-audience risks matter. |
| NSA MCP Security Design Considerations | Server capability drift, bearer token lifecycle gaps, replay/session risks, and tool invocation logging require controls outside protocol defaults. |
| MITRE ATLAS | Agentic threats are better treated as tactics and techniques than as isolated prompt failures. |
| NIST AI 600-1 | Provenance, integrity, TEVV, limitations, and human interaction with provenance should be measured and documented. |
| A2A and AGNTCY identity work | Agent discovery, opaque collaboration, Agent Cards, and verifiable identity motivate identity and capability checks. |

Primary references:

- <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- <https://genai.owasp.org/resource/aiuc-1-crosswalks-owasp-top-10-for-agentic-applications/>
- <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- <https://owasp.org/www-project-agentic-skills-top-10/>
- <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- <https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF>
- <https://atlas.mitre.org/>
- <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- <https://github.com/a2aproject/A2A>
- <https://docs.agntcy.org/identity/identity/>

## Mental Model

The attacker does not need to "break the model" in a cinematic way. The attacker
only needs the system to make one unsafe transition:

```text
content -> context
context -> instruction
instruction -> authority
authority -> action
action -> memory / audit / replay
```

The defender therefore asks:

1. What entered the system?
2. Which role did the receiver assign to it?
3. Did trust increase?
4. Did authority increase?
5. Did a capability appear?
6. Did action happen or become possible?
7. Can a reviewer reconstruct why?

If the answer is not reconstructable, the system may still sound safe while its
control evidence has already collapsed.

## Formal State Model

One transfer state is modeled as:

```text
S_i = (
    channel_i,
    payload_kind_i,
    consumed_as_i,
    trust_i,
    authority_i,
    identity_i,
    capability_i,
    approval_i,
    provenance_i,
    parent_i,
    time_i,
    audit_i
)
```

A chain is an ordered sequence:

```text
C = S_0 -> S_1 -> ... -> S_n
```

`S_0` may be a legitimate root task. It is not automatically suspicious. The
model therefore scores transitions and later states rather than treating the
initial task as an attack by itself.

For each transition `S_i -> S_j`, the verifier checks these invariants:

| Invariant | Violation shape |
|---|---|
| Channel preservation | Data/evidence/memory becomes instruction/policy/capability. |
| Trust monotonicity | Trust increases without verifier provenance and verified identity. |
| Authority monotonicity | Authority increases beyond the parent task or approval. |
| Capability binding | Capability exceeds envelope authority or floats unbound. |
| Approval binding | Approval id is reused for a different action. |
| Replay safety | Parent, time, or memory relation makes stale state current again. |
| Audit reconstructability | Actor/action/source chain cannot be replayed by a reviewer. |

The model treats a theoretical compromise as present when at least one unsafe
transition appears and the transition is supported by inspectable evidence:

```text
compromise_signal(C) =
    role_confusion
 OR trust_promotion_without_evidence
 OR authority_or_capability_gain_without_binding
 OR replay_or_persistence_without_freshness
 OR evidence_degradation_that_blocks_review
```

This is not proof that an attacker succeeded in a real system. It is proof that
the declared transfer chain contains a security-relevant state transition that a
safe receiver should downgrade, block, or force into human review.

## What Counts As Evidence

The model distinguishes an alert from evidence.

An alert is a label such as `authority_escalation`. Evidence is the set of
artifacts that lets a reviewer confirm the alert:

| Evidence artifact | Why it matters |
|---|---|
| `envelope` | Shows the declared producer, consumer, payload kind, trust, authority, and consumption mode. |
| `parent_child_edge` | Shows before/after trust and authority movement. |
| `risk_profile` | Shows which dimensions produced the score. |
| `violation_code` | Gives a stable machine-readable signal. |
| `provenance_chain` | Shows actor/action/source history or its absence. |
| `approval_binding` | Shows whether approval stayed tied to the intended action. |
| `capability_grant` | Shows whether capability is scoped, bound, and within authority. |
| `scenario_trace` | Shows how the synthetic chain reproduced the condition. |

The verifier should prefer fewer high-quality artifacts over many vague labels.

## Detection Logic

The model is intentionally structural:

```text
observe transfer fields
-> compare parent and child state
-> emit violation signals
-> map signals to attack-chain phases
-> calculate chain assessment
-> preserve evidence for reviewer replay
```

It avoids semantic payload scanning as the primary defense because natural
language can be paraphrased endlessly. The stable part is the transition:

- what was the source role?
- how was it consumed?
- what authority appeared?
- what evidence justified the upgrade?
- can the decision be replayed?

## Adversary Roles

The model uses abstract adversary roles, not live attackers:

| Role | What they can influence | Typical boundary failure |
|---|---|---|
| `external_content_author` | Repository text, documents, browser pages, OCR/ASR content. | Data is consumed as instruction. |
| `compromised_tool_or_server` | Tool output, tool metadata, resource content, Agent Card. | Observation becomes permission or capability. |
| `memory_writer` | Stored memory, summaries, handoff notes. | Old or contaminated state becomes policy. |
| `delegated_agent` | Agent-to-agent summary or subtask result. | Another agent's conclusion becomes verified authority. |
| `skill_or_package_publisher` | Skill manifest, package metadata, install-time behavior. | Execution layer hides authority in installed behavior. |
| `internal_user_or_operator` | Approvals, configuration, task routing. | Narrow approval becomes broad authority. |
| `stale_state_replayer` | Old context, parent links, prior decisions. | Expired authority is replayed as current. |
| `confused_client` | Client/runtime interpretation. | The receiver loses channel labels and parent relation. |

These roles intentionally overlap. A real incident can combine several roles.

## Attack Chain Phases

The public model uses six phases.

### 1. Ingress

Untrusted or weakly trusted material enters an agent workflow.

Examples:

- repository file text;
- tool result;
- Agent Card;
- memory record;
- summary from another agent;
- approval record;
- skill metadata.

Defensive question:

> What material entered, from which actor/action/source chain, and under what
> declared trust level?

Main signals:

- `agent_card_without_identity`
- `profile_missing_provenance`
- `profile_partial_provenance`

### 2. Role Confusion

The receiver consumes content under a stronger role than the source justified.

Examples:

- data -> instruction;
- memory -> policy;
- summary -> verified evidence;
- metadata -> capability grant.

Defensive question:

> Did the receiver keep the content's channel label, or did it silently promote
> the content into instruction, policy, or capability?

Main signal:

- `data_consumed_as_instruction`

### 3. Trust Promotion

The transfer claims a higher trust state without enough verifier evidence.

Examples:

- `user_confirmed -> verified`;
- `tool_observed -> signed`;
- delegated summary treated as attested result.

Defensive question:

> What verifier, identity claim, signature, or attestation explains the trust
> increase?

Main signals:

- `unauthorized_trust_promotion`
- `verified_without_identity`
- `unverified_identity_claim`
- `identity_subject_mismatch`
- `identity_without_binding`

### 4. Authority Or Capability Gain

The transfer carries more authority than the parent task allowed.

Examples:

- read task becomes write action;
- Agent Card advertises write capability and the receiver treats it as granted;
- approval for one action is reused for another;
- weakly trusted tool output reaches write/execute/admin authority.

Defensive question:

> Did authority or capability expand beyond the original task, approval, or
> envelope?

Main signals:

- `authority_escalation`
- `weak_trust_authority`
- `capability_exceeds_authority`
- `unbound_capability`
- `approval_laundering`

### 5. Action Or Persistence

The unsafe transition becomes an action, durable memory, replayable state, or
future policy.

Examples:

- stale memory self-parents into a later run;
- a parent mismatch hides where the decision came from;
- action request inherits authority from an unrelated chain.

Defensive question:

> Did the transfer enable action, replay, or persistent authority?

Main signals:

- `self_replay`
- `parent_mismatch`
- freshness/replay dimension above zero

### 6. Evidence Degradation

The system loses enough trace detail that the reviewer cannot reconstruct the
decision.

Examples:

- missing provenance;
- summary drops source and actor;
- approval binding is present but not connected to approval id;
- tool action logs lack parameters or identity.

Defensive question:

> Can a reviewer replay the decision from envelope, parent edge, provenance,
> approval, capability, and violation artifacts?

Main signals:

- `profile_missing_provenance`
- `profile_partial_provenance`
- auditability dimension above zero

## Chain Scoring

`assess_attack_chain(...)` combines three ideas:

```text
chain_score =
    0.50 * expected_signal_coverage
  + 0.25 * phase_coverage
  + 0.25 * strongest_transfer_profile
```

Meaning:

- expected signal coverage: did the chain produce the signals it was designed
  to test?
- phase coverage: how many attack-chain phases are represented?
- strongest transfer profile: how severe was the most risky envelope boundary?

Risk levels:

| Score | Level |
|---:|---|
| `0.0` | `none` |
| `0.0 < score < 0.45` | `low` |
| `0.45 <= score < 0.75` | `medium` |
| `0.75 <= score <= 1.0` | `high` |

This is not a probability. It is a deterministic research index for comparing
synthetic chain cases.

## Built-In Chain Corpus

`attack_chain_corpus()` currently includes six cases:

| Chain | Role | Expected result |
|---|---|---|
| `repo_text_to_tool_write` | `external_content_author` | Repository-controlled text is reinterpreted as write-capable tool authority. |
| `tool_metadata_to_capability` | `compromised_tool_or_server` | Tool or Agent Card metadata becomes an unbound capability grant. |
| `memory_replay_to_policy` | `stale_state_replayer` | Stale memory becomes current write policy. |
| `approval_reuse_to_action` | `internal_user_or_operator` | Narrow approval is reused for a different action. |
| `delegated_agent_identity_drift` | `delegated_agent` | Delegated-agent summary claims verified executable authority. |
| `audit_gap_after_summary` | `confused_client` | Summary loses enough provenance to block review. |

Example:

```python
from agentic_transfer_verifier import assess_attack_chain, attack_chain_corpus

for chain in attack_chain_corpus():
    assessment = assess_attack_chain(chain)
    print(chain.name, assessment.level, assessment.observed_signals)
```

## Detection Matrix

| Failure class | Minimum evidence | Strong evidence |
|---|---|---|
| Data became instruction | `payload_kind`, `consumed_as`, violation code | Parent edge shows source was untrusted or tool-observed. |
| Trust was promoted | Parent/child trust levels | Verifier provenance and verified identity are absent or mismatched. |
| Authority escalated | Parent/child authority levels | Approval/capability binding does not justify escalation. |
| Capability drift | Capability grant exceeds envelope authority | Grant is unbound, has no expiry, and came from weak metadata. |
| Approval laundering | `approval_id`, `approval_binding`, payload action | Payload action differs from approval binding. |
| Replay/persistence | Parent link, timestamps, memory mode | Self-parenting or parent mismatch appears in risk profile. |
| Evidence degradation | Missing provenance or audit fields | Reviewer cannot reconstruct actor/action/source chain. |

## Framework Mapping

The model does not claim one-to-one compliance with any framework. The mapping
is used to keep vocabulary grounded and to show which external risk families a
signal supports.

| Verifier signal | OWASP LLM relation | OWASP Agentic relation | Skills / MCP relation | Detection meaning |
|---|---|---|---|---|
| `data_consumed_as_instruction` | Prompt injection, insecure output handling | Goal hijack, insecure inter-agent communication | Tool/skill content interpreted as behavior | The receiver lost the boundary between content and command. |
| `unauthorized_trust_promotion` | Overreliance, supply-chain risk | Trust exploitation, rogue/delegated agent | Unverified skill or server metadata | The chain accepted a stronger trust state than evidence supports. |
| `verified_without_identity` | Supply-chain risk | Identity and privilege abuse | Missing publisher/server identity | Trust is declared without a verifiable subject. |
| `authority_escalation` | Excessive agency | Tool misuse, privilege abuse | Tool invocation or skill permission expansion | Authority grew beyond the parent task. |
| `weak_trust_authority` | Excessive agency, insecure plugin design | Tool misuse | Weakly trusted tool output reaches action layer | Low-trust content reached write/execute/admin capability. |
| `capability_exceeds_authority` | Insecure plugin design | Privilege abuse, supply-chain risk | Skill/tool permission mismatch | Capability is broader than the envelope authority. |
| `unbound_capability` | Insecure plugin design | Tool misuse | Skill permission lacks binding | Capability is not tied to a specific action or approval. |
| `approval_laundering` | Overreliance | Goal hijack, privilege abuse | Human approval is reused outside scope | Approval stopped binding to the exact action. |
| `self_replay` | Training/context poisoning | Memory poisoning, cascading failure | Agent memory/log state reused | Old state becomes current control input. |
| `parent_mismatch` | Overreliance | Insecure inter-agent communication | Broken task/session lineage | The claimed handoff parent is not the supplied context. |
| `profile_missing_provenance` | Supply-chain risk | Governance and monitoring gap | Missing tool/skill invocation lineage | The chain cannot be reconstructed. |

## Minimal Defensive Invariants

A receiving agent or runtime should be able to enforce these invariants before
acting:

1. **No instruction without channel authority.** Text from tools, files, memory,
   browser pages, OCR/ASR, or another agent remains data/evidence unless an
   explicit trusted channel grants instruction status.
2. **No trust upgrade without evidence.** Trust can increase only when verifier
   provenance and verified identity explain the transition.
3. **No capability without binding.** Capability must be scoped, bounded to a
   task/action/envelope, and not stronger than envelope authority.
4. **No approval reuse.** Approval must stay bound to the exact action or
   payload it approved.
5. **No stale authority.** Memory, parent links, and approvals need freshness or
   expiry semantics before they influence current policy.
6. **No invisible decisions.** Every accept/downgrade/reject decision needs
   enough evidence for reviewer replay.

These invariants are intentionally stricter than many real agent runtimes. That
is the point: the verifier models where a defensive runtime should stop and ask
for stronger evidence.

## False Positives

Expected false positives:

- A legitimate summary may have missing provenance because the runtime never
  produced it.
- A legitimate admin workflow may intentionally increase authority.
- Some local single-user systems may use weak identity because the user accepts
  local trust.
- A capability can exceed envelope authority during dry-run planning if it is
  never executable.

The verifier should not automatically block everything. It should make the weak
assumption visible.

## False Negatives

Expected false negatives:

- A malicious envelope can be well formed.
- Natural-language intent can hide behind safe-looking metadata.
- A real signature can still sign bad content.
- A verifier can be compromised.
- The model does not inspect live runtime side effects.
- The model cannot prove that a model internally understood channel hierarchy.

This is why the evidence model matters: structural checks should be combined
with runtime traces, tool invocation logs, and policy enforcement.

## Public / Private Split

Public repository should include:

- abstract chain phases;
- synthetic chain cases;
- detection signal taxonomy;
- safe examples without real targets;
- defensive assumptions and limits.

Private research may include:

- detailed adversarial prompts;
- provider-specific behavior;
- timing, multi-agent race, or evasion experiments;
- traces involving private systems;
- sensitive scoring calibration.

The public model should be enough to understand and reproduce the defensive
logic without becoming an offensive playbook.

## Relationship To v0.2

v0.2 asks:

> Is this transfer envelope risky?

The adversarial model asks:

> Which phase of a theoretical compromise does this transfer support, and what
> evidence proves it?

The two are meant to be read together:

```text
TransferEnvelope -> TransferRiskProfile -> AttackChainCase -> ChainAssessment
```

## Research Next

- Add JSON fixtures for adversarial chains.
- Add trace export for chain assessments.
- Map each signal to OWASP Agentic Application and OWASP LLM categories.
- Add benign counterexamples for false-positive calibration.
- Add a private calibration notebook or document for deeper scoring work.
