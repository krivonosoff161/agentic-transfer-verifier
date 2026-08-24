# Package and CI contract

`agentic-transfer-verifier` is a source package with a public Python API. It does not
currently define a console-script entry point and is not yet an installable Harness
extension. CI therefore exercises the installed Python contract rather than inventing a
CLI surface.

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
8. a no-dependency wheel installation and installed-package verification smoke in a
   fresh virtual environment outside the checkout.

The workflow actions are pinned to exact commits and receive read-only repository
contents permission. `persist-credentials` is disabled after checkout.

These controls establish reproducible package and contract behavior for the tested
matrix. They do not prove that the package is free of all secrets or vulnerabilities,
authenticate transfer producers, provide a sandbox, or grant operational authority.
Publishing to an index, release tagging, Harness activation, provider calls, and
deployment remain separate gates.
