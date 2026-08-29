# Transfer Verifier Harness Extension V1

## Status and scope

This repository owns a review-only candidate distribution at
`extensions/transfer_harness_extension_v1`. It is built separately from the standalone
`agentic-transfer-verifier` wheel. The candidate exposes exactly one entry point:

```text
agentic_security_harness.extensions.v1
  agentic-transfer-verifier.verification =
    agentic_transfer_verifier_extension:build_extension
```

The entry point declaration does not load code. `build_extension` is a repository-local
convention, not a factory signature guaranteed by Harness V1.

## Data flow and verdict meaning

The extension accepts a validated `ExtensionObservationEnvelopeV1`. It selects only
activities beginning with `transfer.`, constructs a `TransferEnvelope` projection from
the event id, producer digest, activity, source surface, timestamp, and
`data_envelope_ref`, and delegates that projection to the existing deterministic
`verify_envelope` API.

No raw transfer payload enters the extension. A `pass` therefore means only that the
digest-only projection satisfies those structural checks. It does not prove the original
payload, provenance, producer, trust, approval, capability, or authority claim. Missing
or non-complete telemetry is `inconclusive`; unmatched activities are also
`inconclusive`. Evidence remains `producer_declared`, all results are advisory-only, and
operational authority is always `none`.

## Explicit operator flow

1. Build the nested wheel and install it into a dedicated local staging root with
   bytecode compilation disabled. Copy the resulting regular files byte-for-byte into
   a quiescent operator-owned inspection snapshot before inspection. Distribution
   Discovery V1 rejects generated `__pycache__` additions because they are outside the
   signed `RECORD` closure.
2. Inspect the exact distribution name, extension id, search root, and canonical
   `configuration.json` bytes. Inspection imports no extension code.
3. Approve the exact inspection id. Approval immediately repeats the metadata and file
   inspection and still loads no code.
4. Retain the approval, manifest, and configuration bytes. Explicitly import only the
   approved module and call its declared factory with those bytes.
5. Bind the constructed object to the approval receipt through the Harness lifecycle,
   then run it through the Extension SDK.

The synthetic cross-repository test performs this entire sequence. Production code in
this repository performs no automatic discovery, import, download, or activation.

## Coordinated source installation

Build and install both source candidates explicitly:

```text
python -m build --outdir dist/core .
python -m build --no-isolation --outdir dist/extension extensions/transfer_harness_extension_v1
python -m pip install --no-deps dist/core/agentic_transfer_verifier-0.2.0-py3-none-any.whl dist/extension/agentic_transfer_verifier_harness_extension-1.0.0-py3-none-any.whl
```

Harness `main` already declares a source-only `transfer` extra selecting these same two
exact distributions. Neither companion artifact is published and published Harness
`v1.3.0` metadata does not contain that extra, so the public extra command is unavailable.
The extension intentionally has no `Requires-Dist`; a later published extra, not ambient
dependency resolution, must install the compatible pair.

## Package and supply-chain boundary

The wheel uses exact `Requires-Python: >=3.11,<3.14`, `py3-none-any`, one top-level
implementation module, one entry-point group, a canonical manifest inside `.dist-info`,
and a regenerated exact `RECORD`. Current Harness Distribution Discovery V1 requires no
`Requires-Dist`; therefore the source `agentic-security-harness>=1.3,<2` boundary is
declared in source metadata and the generated contract, not installed automatically.

The canonical configuration binds the complete Python runtime file inventory and SHA-256
digests of `agentic-transfer-verifier` 0.2.0. The factory checks those installed files
before importing the deterministic API. This reduces ambient dependency drift but is not
a signature, sandbox, in-memory code attestation, or defense against a hostile process
that can replace code during import. The embedding application must provide a trusted,
operator-controlled local environment.

## Verification

- generator drift check for exact implementation, configuration, Harness source, and
  manifest digests;
- real sdist and wheel build with isolated `--no-index --no-deps --no-compile` install
  followed by a content-identical quiescent inspection snapshot;
- Harness inspect, approve, explicit factory construction, lifecycle bind, and SDK run;
- Linux and Windows testing on Python 3.11, 3.12, and 3.13;
- Ruff, mypy, Bandit, public-tree secret hygiene, package tests, and RECORD assertions.

No companion release, provider call, live transfer input, deployment, or enforcement is
granted by this source candidate or by the merged Harness optional-dependency row.
