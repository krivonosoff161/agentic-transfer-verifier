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

Ecosystem integration is currently **`extension_candidate`**. A separate nested wheel
implements the exact Harness Extension SDK and Distribution Discovery V1 contracts and
is tested against the pinned Lifecycle head on Linux and Windows. The standalone package
still registers no Harness entry point, and the extension candidate is not released,
automatically loaded, signed, sandboxed, or enabled by installing the core package.

The coordinated source candidates are `agentic-transfer-verifier==0.2.0` and
`agentic-transfer-verifier-harness-extension==1.0.0`. CI builds both exact artifact sets;
public index publication and the Harness optional-dependency row remain separate release gates.

## Ordered delivery gates

1. **Documentation convergence — active.** Keep this roadmap, `component.yaml`, README,
   and offline manifest tests synchronized with the central ecosystem contract.
2. **Extension contract — candidate complete.** The nested distribution owns one exact
   entry point, canonical config/manifest bytes, digest-only findings, and no authority.
3. **Installable extension — candidate complete.** Synthetic wheels are inspected,
   approved, explicitly constructed, bound, and exercised on Linux and Windows. This is
   build evidence, not a public release.
4. **Suite verification — candidate complete.** Cross-repository tests pin the exact
   Harness Lifecycle source head and runtime contract digests. Promotion to a released
   compatibility row remains a separate release gate.
5. **Research deepening — separately reviewed.** Continue transfer-integrity research only
   through synthetic, invariant-led cases with explicit evidence and non-claims.

No later gate is satisfied by documentation alone.

## Compatibility policy

- Standalone package metadata supports Python 3.10 and later.
- The initial ecosystem compatibility contour is Python 3.11 or later on Linux and
  Windows.
- The nested candidate implements Harness API `1` and records a future package boundary
  `agentic-security-harness>=1.3,<2`. Current Distribution Discovery V1 forbids
  `Requires-Dist`, so this is a compatibility declaration, not automatic installation.

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
models and synthetic fixtures. The extension PASS applies only to a digest-only
projection of a canonical observation; it does not re-open or verify the original raw
transfer payload. The component does not authenticate producer identity, establish
semantic truth, estimate incident probability, provide a sandbox, enforce production
policy, or grant operational authority.

