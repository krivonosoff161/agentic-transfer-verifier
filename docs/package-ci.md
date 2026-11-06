# Package and CI contract

`agentic-transfer-verifier==0.2.1` is the immutable published Python API package.
This source branch prepares an unpublished core 0.3.0 candidate with a console-script
entry point and four local synthetic examples. The optional published Harness extension
remains a separate distribution pinned to the published 0.2.1 core contract.

For every supported Python version (3.10, 3.11, and 3.12), the workflow runs on both
Ubuntu and Windows and performs:

1. Ruff and Bandit static checks;
2. a bounded supplemental public-tree hygiene scan that reports rule identifiers and
   locations, never matching values;
3. source-owned component and vendored contract-pin tests;
4. the complete synthetic test suite;
5. independent sdist and wheel builds;
6. archive path/link/size checks, including the sdist review/contract surface;
7. the shipped synthetic tests from a safely reconstructed sdist tree; and
8. a no-dependency wheel installation and installed-package verification smoke,
   including the actual console script, in a fresh virtual environment outside the checkout.

The workflow actions are pinned to exact commits and receive read-only repository
contents permission. `persist-credentials` is disabled after checkout.

These controls establish reproducible package and contract behavior for the tested
matrix. They do not prove that the package is free of all secrets or vulnerabilities,
authenticate transfer producers, provide a sandbox, or grant operational authority.
Publishing to an index, release tagging, Harness activation, provider calls, and
deployment remain separate gates.

The core release workflow accepts only tag `v0.3.0` for this source version. Its
closed release set is the core 0.3.0 wheel and sdist plus checksums, with exact
artifact, attestation, index-hash, and clean-install gates. It does not build or
republish extension 1.0.1. The historical extension publication workflow explicitly
requires its original `v0.2.1` tag and 0.2.1/1.0.1 artifact closure; it rejects a
new core tag. A local 0.3.0 wheel is a candidate, not evidence of index availability.
