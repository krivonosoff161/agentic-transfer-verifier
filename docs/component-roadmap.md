# Agentic Transfer Verifier component roadmap

This is the source-owned roadmap for `agentic-transfer-verifier`. The public ecosystem
sequence and cross-repository dependencies are owned by the
[Agentic Security Harness ecosystem roadmap](https://github.com/krivonosoff161/agentic-security-harness/blob/main/docs/ecosystem-roadmap.md).
The machine-readable component boundary is [`component.yaml`](../component.yaml).

## Current component boundary

The repository currently ships a local Python package with deterministic structural
checks for transfer envelopes, provenance, trust transitions, freshness, approval,
capability, authority non-expansion, adversarial transfer chains, and private-asset sink
policy. Its portfolio-observation adapter is authority-free.

Ecosystem integration is currently **`contract_only`**. The package does not yet implement
the future Harness Extension SDK, does not register runtime entry points with `ash`, and
must not be described as an installable Harness extension today.

## Ordered delivery gates

1. **Documentation convergence — active.** Keep this roadmap, `component.yaml`, README,
   and offline manifest tests synchronized with the central ecosystem contract.
2. **Extension contract — planned.** After Harness publishes a stable Extension SDK,
   define versioned check descriptors for the existing deterministic checks without
   changing their security meaning.
3. **Installable extension — planned.** Register explicit package entry points, return the
   common evidence/result contract, and prove source-package installation on Linux and
   Windows.
4. **Suite verification — planned.** Add cross-repository compatibility tests against a
   pinned Harness release and publish a compatibility row backed by those tests.
5. **Research deepening — separately reviewed.** Continue transfer-integrity research only
   through synthetic, invariant-led cases with explicit evidence and non-claims.

No later gate is satisfied by documentation alone.

## Compatibility policy

- Standalone package metadata supports Python 3.10 and later.
- The initial ecosystem compatibility contour is Python 3.11 or later on Linux and
  Windows.
- Harness API compatibility is `not-yet-declared` until an executable Extension SDK
  contract and cross-repository test exist.

## Document authority

- `component.yaml` and this page own this repository's ecosystem identity and local
  delivery sequence.
- `docs/research-roadmap.md` remains a research question map, not product status.
- `docs/roadmap.md` is retained as superseded version-planning history.
- The three `docs/security-portfolio-roadmap*` artifacts are preserved historical,
  digest-bound R4 projections. They remain evidence of the earlier portfolio contract and
  do not override the current public ecosystem roadmap.

## Claims and non-claims

The component may claim deterministic structural verification over its declared local
models and synthetic fixtures. It does not authenticate producer identity, establish
semantic truth, estimate incident probability, provide a sandbox, enforce production
policy, or grant operational authority.

