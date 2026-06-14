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
- optional approval and parent-envelope fields

The envelope is not encryption. It is a policy and audit structure. Real systems
can later add signatures, hashes, identity, and storage-specific guarantees.
