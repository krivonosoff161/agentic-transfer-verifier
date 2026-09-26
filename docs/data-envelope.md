# Data Envelope

The first envelope is intentionally small:

- `envelope_id`
- `producer`
- `consumer`
- `payload_kind`
- `trust_level`
- `authority_scope`
- `payload`
- `provenance`
- `consumed_as`
- `allowed_uses`
- optional identity claims
- optional capability grants
- optional approval and parent-envelope fields

The envelope is not encryption. It is a policy and audit structure. Real systems
can later add signatures, hashes, identity, and storage-specific guarantees.

v0.2 keeps identity and capability fields as declared local structures:

- identity claims are not externally resolved;
- capability grants are checked for scope and binding, not executed;
- `signed` and `attested` trust levels are declarations until a real verifier
  adapter exists.

## Unreleased JSON loader

`load_json_envelope(bytes)` maps one JSON object to the existing `TransferEnvelope`
model. The required keys are `envelope_id`, `producer`, `consumer`, `payload_kind`,
`trust_level`, `authority_scope`, and the `payload` object. Other model fields may
be omitted and take their dataclass defaults. `provenance`, `identity_claims`, and
`capabilities` are arrays of model-shaped objects.

The loader rejects duplicate or unknown model fields, invalid enum values, wrong
types, invalid UTF-8, non-finite numbers, unpaired Unicode surrogates, JSON over
65,536 bytes, nesting over 64 levels, model arrays over 64 items, and integers over
256 decimal digits (independently of Python's global integer setting). It does not
make semantic verification findings: for example, an empty provenance array is a
valid envelope structure that the verifier reports as `FAIL`. Error messages omit
input values. Arbitrary JSON payload contents are data only and are never run.
The four files under `examples/` are synthetic local records and grant no authority.
