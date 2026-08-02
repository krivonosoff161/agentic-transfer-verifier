# Security Portfolio canonical adapter

The Transfer Verifier P1 adapter is a local, deterministic, downgrade-only projection from
the complete `TransferEnvelope` JSON representation to the Harness-owned
`portfolio-observation-v1.0` shape.

## Boundary

The source loader accepts UTF-8 JSON bytes only. It rejects duplicate, unknown, missing and
wrongly typed fields, unsupported enum values, non-finite JSON numbers, over-sized input,
missing creation time, naive timestamps, impossible timestamps and expiry before creation.
Nested provenance, identity and capability records also require exact fields and types.
Source collections are bounded to 64 items. The emitted canonical observation enforces the
owner manifest's 4,096-byte wire limit, 64-item entity/parent limits, and 128/64-item adapter
audit limits. These are fail-closed interoperability bounds, not authority decisions.

The adapter deliberately does **not** authenticate source declarations:

- `verified`, `signed` and `attested` remain declared trust labels;
- identity claims remain declared claims;
- authority scope and capability grants are dropped;
- approval identifiers do not become consent;
- provenance text does not become producer attestation;
- raw payload is never emitted; only a SHA-256 pointer over canonical JSON bytes is emitted;
- `producer_attestation=unattested`, `authority_envelope_ref=null` and
  `operational_authority=none` are constants.

Project id, repository id, exact repository object id, source surface, data-envelope binding
and telemetry state come from an explicit `TransferAdapterContext`. Context values are not
source evidence and are recorded separately in the adapter audit.

## Loss accounting

Every source and target field is classified exactly once by `AdapterAuditV1`:

- `mappings` names source dependencies and their derived target fields;
- `dropped_source_fields` records source information that cannot cross safely;
- `context_target_fields` records explicit caller context;
- `constant_target_fields` records authority-free constants.

The projection is always `partial`, always has `authority_downgrade=true`, and always has
`operational_authority=none`. The audit shape mirrors the current Harness owner implementation
of `portfolio-adapter-audit-v1.0`.

## Contract pin

The exact Harness-owner schema bytes are vendored at
`contracts/portfolio-observation.v1.schema.json`. The local owner pin records schema SHA-256
`19371f188b080accfdac489e985b9642f547c3300c0b56b44527eb97f550c26f`. Exact manifest bytes
are vendored at `contracts/portfolio-observation.v1.manifest.json` with SHA-256
`fecbe08da3e48250aaeff2ea19bf50efdbd2c3aa532af9cae8be50b4c8321554`.
The pin proves byte identity only; it does not turn a worktree, roadmap or manifest into
operational authority.

## Non-claims

This adapter is not authentication, cryptographic provenance, semantic truth detection,
consent verification, enforcement, an allow decision or an execution receipt. Hashes minimize
and bind bytes but do not make low-entropy values anonymous.
