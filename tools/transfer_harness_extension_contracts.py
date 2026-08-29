"""Generate the canonical Transfer Harness extension and source-pin manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXTENSION_ROOT = ROOT / "extensions" / "transfer_harness_extension_v1"
MODULE = EXTENSION_ROOT / "agentic_transfer_verifier_extension.py"
CONFIGURATION = EXTENSION_ROOT / "configuration.json"
EXTENSION_MANIFEST = EXTENSION_ROOT / "ash-extension-manifest.json"
CONTRACT_MANIFEST = ROOT / "contracts" / "transfer-harness-extension.v1.manifest.json"

HARNESS_REPOSITORY = "https://github.com/krivonosoff161/agentic-security-harness"
HARNESS_COMMIT = "c1dd69856212458ae952e43aeb2b0cc9290e8205"
HARNESS_TREE = "596c189e8b15ceaf7bf28337546655e23d47d3ef"
HARNESS_FILES = (
    "src/agentic_security_harness/extension_sdk.py",
    "src/agentic_security_harness/extension_distribution.py",
    "src/agentic_security_harness/extension_lifecycle.py",
    "src/agentic_security_harness/portfolio_contract.py",
)
LOCAL_CLOSURE_FILES = (
    ".gitattributes",
    ".github/workflows/tests.yml",
    "MANIFEST.in",
    "README.md",
    "component.yaml",
    "docs/component-roadmap.md",
    "docs/transfer-harness-extension.md",
    "extensions/transfer_harness_extension_v1/README.md",
    "extensions/transfer_harness_extension_v1/backend.py",
    "extensions/transfer_harness_extension_v1/pyproject.toml",
    "pyproject.toml",
    "tests/test_ecosystem_component_contract.py",
    "tests/conftest.py",
    "tests/test_transfer_harness_extension_v1.py",
    "tools/transfer_harness_extension_contracts.py",
)


def generated_files(harness_root: Path) -> dict[Path, bytes]:
    module = _exact_lf_bytes(MODULE)
    configuration = _canonical_existing_json(CONFIGURATION)
    extension = {
        "schema_version": "harness-extension-manifest-v1.0",
        "extension_id": "agentic-transfer-verifier.verification",
        "extension_version": "1.0.1",
        "component_id": "agentic-transfer-verifier",
        "implementation_sha256": hashlib.sha256(module).hexdigest(),
        "configuration_sha256": hashlib.sha256(configuration).hexdigest(),
        "harness_api": "1",
        "kind": "check_extension",
        "capabilities": ["observation.read", "finding.emit"],
        "consumes": [{"contract_id": "portfolio-observation", "version": "1.0", "required": True}],
        "produces": [{"contract_id": "extension-finding", "version": "1.0", "required": True}],
        "deterministic": True,
        "evidence_provenance": "producer_declared",
        "network_mode": "off",
        "raw_data_policy": "digests_only",
        "execution_model": "in_process_operator_approved_not_sandboxed",
        "operational_authority": "none",
    }
    extension_bytes = _canonical_bytes(extension)
    harness_bindings = []
    for relative in HARNESS_FILES:
        harness_bindings.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(_canonical_lf_bytes(harness_root / relative)).hexdigest(),
            }
        )
    local_closure = [
        {
            "path": relative,
            "canonical_lf_sha256": hashlib.sha256(_canonical_lf_bytes(ROOT / relative)).hexdigest(),
        }
        for relative in LOCAL_CLOSURE_FILES
    ]
    contract = {
        "schema_version": "transfer-harness-extension-contract-v1.0",
        "component_id": "agentic-transfer-verifier",
        "distribution_name": "agentic-transfer-verifier-harness-extension",
        "extension_id": "agentic-transfer-verifier.verification",
        "extension_version": "1.0.1",
        "requires_python": ">=3.11,<3.14",
        "future_harness_package_boundary": ">=1.3,<2",
        "harness_api": "1",
        "harness_source": {
            "repository": HARNESS_REPOSITORY,
            "commit": HARNESS_COMMIT,
            "tree": HARNESS_TREE,
            "byte_semantics": "utf8-canonical-lf",
            "files": harness_bindings,
        },
        "extension_files": [
            {
                "path": str(MODULE.relative_to(ROOT)).replace("\\", "/"),
                "sha256": hashlib.sha256(module).hexdigest(),
            },
            {
                "path": str(CONFIGURATION.relative_to(ROOT)).replace("\\", "/"),
                "sha256": hashlib.sha256(configuration).hexdigest(),
            },
            {
                "path": str(EXTENSION_MANIFEST.relative_to(ROOT)).replace("\\", "/"),
                "sha256": hashlib.sha256(extension_bytes).hexdigest(),
            },
        ],
        "source_closure": local_closure,
        "source_closure_byte_semantics": "utf8-canonical-lf",
        "evidence_provenance": "producer_declared",
        "raw_data_policy": "digests_only",
        "network_mode": "off",
        "operational_authority": "none",
        "non_claims": [
            "sandbox",
            "signature",
            "authenticated-producer",
            "allow-decision",
            "enforcement",
        ],
    }
    return {EXTENSION_MANIFEST: extension_bytes, CONTRACT_MANIFEST: _canonical_bytes(contract)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness-root", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = generated_files(args.harness_root.resolve())
    drift = []
    for path, expected in generated.items():
        if args.check:
            if not path.is_file() or path.read_bytes() != expected:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
    if drift:
        raise SystemExit("generated extension contract drift: " + ", ".join(drift))
    return 0


def _canonical_existing_json(path: Path) -> bytes:
    payload = path.read_bytes()
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON: {path.name}") from exc
    canonical = _canonical_bytes(value)
    if payload != canonical:
        raise ValueError(f"JSON is not canonical: {path.name}")
    return payload


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _exact_lf_bytes(path: Path) -> bytes:
    payload = path.read_bytes()
    if b"\r" in payload:
        raise ValueError(f"non-LF source is forbidden: {path.name}")
    return payload


def _canonical_lf_bytes(path: Path) -> bytes:
    payload = path.read_bytes().replace(b"\r\n", b"\n")
    if b"\r" in payload:
        raise ValueError(f"bare CR is forbidden: {path.name}")
    return payload


if __name__ == "__main__":
    raise SystemExit(main())
