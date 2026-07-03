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
