# Transfer Verifier Harness Extension V1

This nested, optional distribution adapts canonical Harness observation envelopes to
the deterministic `agentic-transfer-verifier` API. It accepts only digest-shaped
`data_envelope_ref` values and emits advisory `ExtensionFindingV1` records. It never
loads raw transfer payloads, opens the network, grants authority, or makes an allow or
enforcement decision.

The current Distribution Discovery V1 contract requires a dependency-free wheel, so
the wheel intentionally has no `Requires-Dist`. The embedding application must install
compatible packages separately and explicitly. The declared future packaging boundary
is `agentic-security-harness>=1.3,<2`; the executable SDK contract remains Harness API
`1`. This compatibility declaration is not automatic installation, sandboxing, a
signature, or runtime attestation.

The operator flow is: inspect the installed wheel without importing it, approve the
exact inspection, explicitly load the one approved entry point, call `build_extension`
with the retained canonical manifest and configuration bytes, and bind the constructed
object to the approval receipt. See `docs/transfer-harness-extension.md` in the parent
repository.
