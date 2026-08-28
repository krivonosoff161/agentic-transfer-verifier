from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import types
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXTENSION_ROOT = ROOT / "extensions" / "transfer_harness_extension_v1"
HARNESS_COMMIT = "c1dd69856212458ae952e43aeb2b0cc9290e8205"
HARNESS_TREE = "596c189e8b15ceaf7bf28337546655e23d47d3ef"
DIST_NAME = "agentic-transfer-verifier-harness-extension"
EXTENSION_ID = "agentic-transfer-verifier.verification"


def _harness_root() -> Path:
    value = os.environ.get("ASH_HARNESS_SDK_ROOT")
    if not value:
        pytest.skip("ASH_HARNESS_SDK_ROOT is required for exact cross-repository integration")
    root = Path(value).resolve()
    assert _git(root, "rev-parse", "HEAD") == HARNESS_COMMIT
    assert _git(root, "show", "-s", "--format=%T", "HEAD") == HARNESS_TREE
    assert _git(root, "status", "--porcelain=v1", "--untracked-files=all") == ""
    return root


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "--no-optional-locks", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).stdout.strip()


def _build_and_install(tmp_path: Path) -> tuple[Path, Path]:
    dist = tmp_path / "dist"
    core_dist = tmp_path / "core-dist"
    core_source = _git_source_snapshot(tmp_path)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(core_dist),
            str(core_source),
        ],
        check=True,
        cwd=ROOT,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(dist),
            str(EXTENSION_ROOT),
        ],
        check=True,
        cwd=ROOT,
    )
    wheels = tuple(dist.glob("*.whl"))
    sdists = tuple(dist.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1
    core_wheels = tuple(core_dist.glob("*.whl"))
    assert len(core_wheels) == 1
    pip_target = tmp_path / "pip-installed"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--target",
            str(pip_target),
            str(wheels[0]),
            str(core_wheels[0]),
        ],
        check=True,
        cwd=tmp_path,
    )
    target = tmp_path / "installed"
    _stable_install_snapshot(pip_target, target)
    return wheels[0], target


def _git_source_snapshot(tmp_path: Path) -> Path:
    archive_path = tmp_path / "core-source.tar"
    subprocess.run(
        ["git", "archive", "--format=tar", f"--output={archive_path}", "HEAD"],
        check=True,
        cwd=ROOT,
    )
    destination = tmp_path / "core-source"
    destination.mkdir()
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive.getmembers():
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise AssertionError("git archive member is not a safe relative path")
            output = destination / relative
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise AssertionError("git archive contains a non-file member")
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            assert source is not None
            with source, output.open("wb") as stream:
                shutil.copyfileobj(source, stream)
    for core_source in (destination / "src" / "agentic_transfer_verifier").glob("*.py"):
        payload = core_source.read_bytes().replace(b"\r\n", b"\n")
        if b"\r" in payload:
            raise AssertionError("core source snapshot contains a bare CR")
        core_source.write_bytes(payload)
    return destination


def _stable_install_snapshot(source: Path, destination: Path) -> None:
    source_files: dict[str, str] = {}
    for candidate in source.rglob("*"):
        if candidate.is_symlink():
            raise AssertionError("pip installation contains a link")
        if candidate.is_file():
            relative = candidate.relative_to(source).as_posix()
            source_files[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    shutil.copytree(source, destination, copy_function=shutil.copyfile)
    copied_files = {
        candidate.relative_to(destination).as_posix(): hashlib.sha256(
            candidate.read_bytes()
        ).hexdigest()
        for candidate in destination.rglob("*")
        if candidate.is_file() and not candidate.is_symlink()
    }
    assert copied_files == source_files


def _event(portfolio_contract: Any, *, activity: str, telemetry: str, seed: str) -> Any:
    event_type = portfolio_contract.CanonicalObservationEventV1
    return event_type(
        schema_version="portfolio-observation-v1.0",
        event_id=seed * 64,
        project_id="agentic-transfer-verifier",
        repository_id="krivonosoff161/agentic-transfer-verifier",
        repository_sha="1" * 40,
        occurred_at=datetime(2026, 8, 24, 6, 0, tzinfo=timezone.utc),
        producer_id_hash="2" * 64,
        producer_attestation="unattested",
        source_surface="agent",
        activity=activity,
        entity_refs=(),
        parent_event_ids=(),
        data_envelope_ref="3" * 64,
        authority_envelope_ref=None,
        telemetry_state=telemetry,
        operational_authority="none",
    )


def test_exact_wheel_inspect_approve_bind_and_run_is_advisory_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness_root = _harness_root()
    sys.path.insert(0, str(harness_root / "src"))
    distribution = importlib.import_module("agentic_security_harness.extension_distribution")
    sdk = importlib.import_module("agentic_security_harness.extension_sdk")
    portfolio = importlib.import_module("agentic_security_harness.portfolio_contract")

    wheel, installed = _build_and_install(tmp_path)
    configuration = (EXTENSION_ROOT / "configuration.json").read_bytes()
    module_name = "agentic_transfer_verifier_extension"
    assert module_name not in sys.modules

    inspection = distribution.inspect_extension_distribution_v1(
        distribution_name=DIST_NAME,
        extension_id=EXTENSION_ID,
        search_paths=(installed,),
        configuration_bytes=configuration,
    )
    assert inspection.code_loaded is False
    assert inspection.entry_point_value == f"{module_name}:build_extension"
    assert inspection.requires_python == ">=3.11,<3.14"
    assert inspection.operational_authority == "none"
    assert module_name not in sys.modules

    approval = distribution.approve_extension_distribution_v1(
        approved_inspection=inspection,
        approved_inspection_id=inspection.inspection_id,
        search_paths=(installed,),
        configuration_bytes=configuration,
    )
    assert approval.code_loaded is False
    manifest_path = installed / inspection.manifest_path
    manifest_bytes = manifest_path.read_bytes()
    assert hashlib.sha256(manifest_bytes).hexdigest() == approval.manifest_sha256

    sys.path.insert(0, str(installed))
    for loaded_name in tuple(sys.modules):
        if loaded_name == "agentic_transfer_verifier" or loaded_name.startswith(
            "agentic_transfer_verifier."
        ):
            monkeypatch.delitem(sys.modules, loaded_name)
    implementation = importlib.import_module(inspection.module_name)
    factory = getattr(implementation, inspection.factory_attribute)
    fake_core = types.ModuleType("agentic_transfer_verifier.verifier")
    fake_core.__dict__["verify_envelope"] = lambda value: value
    monkeypatch.setitem(sys.modules, "agentic_transfer_verifier.verifier", fake_core)
    with pytest.raises(implementation.TransferHarnessExtensionError, match="loaded before"):
        factory(manifest_bytes=manifest_bytes, configuration_bytes=configuration)
    monkeypatch.delitem(sys.modules, "agentic_transfer_verifier.verifier")
    extension = factory(
        manifest_bytes=manifest_bytes,
        configuration_bytes=configuration,
    )
    bound = distribution.bind_operator_approved_extension_v1(approval, extension)
    with pytest.raises(AttributeError, match="immutable"):
        extension._verifier = lambda value: value

    complete = _event(portfolio, activity="transfer.verification", telemetry="complete", seed="a")
    complete_envelope = sdk.build_extension_envelope_v1(
        source_component_id="agentic-transfer-verifier",
        source_commitment_sha256="4" * 64,
        events=(complete,),
    )
    receipt = sdk.run_extension_v1(bound, complete_envelope)
    observed = [(item.outcome, item.severity, item.reason_code) for item in receipt.result.findings]
    assert observed == [("pass", "none", "transfer.digest_projection_valid")]
    assert receipt.result.evidence_class == "producer_declared"
    assert receipt.result.verdict_semantics == "advisory_only_no_operational_effect"
    assert receipt.operational_authority == "none"

    incomplete = _event(
        portfolio,
        activity="transfer.verification",
        telemetry="incomplete",
        seed="b",
    )
    incomplete_receipt = sdk.run_extension_v1(
        bound,
        sdk.build_extension_envelope_v1(
            source_component_id="agentic-transfer-verifier",
            source_commitment_sha256="5" * 64,
            events=(incomplete,),
        ),
    )
    assert incomplete_receipt.result.findings[0].outcome == "inconclusive"
    assert incomplete_receipt.result.findings[0].reason_code == "transfer.telemetry_incomplete"

    unrelated = _event(portfolio, activity="handoff.session", telemetry="complete", seed="c")
    unrelated_receipt = sdk.run_extension_v1(
        bound,
        sdk.build_extension_envelope_v1(
            source_component_id="agentic-transfer-verifier",
            source_commitment_sha256="6" * 64,
            events=(unrelated,),
        ),
    )
    assert unrelated_receipt.result.findings[0].outcome == "inconclusive"
    assert unrelated_receipt.result.findings[0].evidence_event_ids == ()

    encoded = json.dumps(
        receipt.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert b"payload" not in encoded
    assert b"C:\\" not in encoded and b"/tmp/" not in encoded
    assert b"allow" not in encoded and b"enforce" not in encoded

    with pytest.raises(implementation.TransferHarnessExtensionError, match="configuration"):
        factory(manifest_bytes=manifest_bytes, configuration_bytes=configuration + b" ")

    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith("/METADATA"))
        metadata = archive.read(metadata_name)
        assert b"Requires-Dist:" not in metadata
        assert metadata.count(b"Requires-Python: >=3.11,<3.14") == 1


def test_generated_contracts_and_extension_source_are_closed() -> None:
    harness_root = _harness_root()
    subprocess.run(
        [
            sys.executable,
            "tools/transfer_harness_extension_contracts.py",
            "--harness-root",
            str(harness_root),
            "--check",
        ],
        check=True,
        cwd=ROOT,
    )
    manifest = json.loads(
        (ROOT / "contracts" / "transfer-harness-extension.v1.manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["harness_source"]["commit"] == HARNESS_COMMIT
    assert manifest["harness_source"]["tree"] == HARNESS_TREE
    assert manifest["future_harness_package_boundary"] == ">=1.3,<2"
    assert manifest["operational_authority"] == "none"
    assert manifest["source_closure_byte_semantics"] == "utf8-canonical-lf"
    generated_contract = "contracts/transfer-harness-extension.v1.manifest.json"
    contract_eol = subprocess.check_output(
        ["git", "check-attr", "eol", "--", generated_contract],
        cwd=ROOT,
        text=True,
    )
    assert contract_eol.strip() == f"{generated_contract}: eol: lf"
    configuration = json.loads((EXTENSION_ROOT / "configuration.json").read_text("utf-8"))
    for binding in configuration["core_distribution"]["runtime_files"]:
        git_blob = subprocess.check_output(["git", "show", f"HEAD:src/{binding['path']}"], cwd=ROOT)
        assert hashlib.sha256(git_blob).hexdigest() == binding["sha256"]
    closure = {item["path"] for item in manifest["source_closure"]}
    assert {
        ".github/workflows/tests.yml",
        "docs/transfer-harness-extension.md",
        "extensions/transfer_harness_extension_v1/backend.py",
        "tests/test_transfer_harness_extension_v1.py",
        "tools/transfer_harness_extension_contracts.py",
    } <= closure
    source = (EXTENSION_ROOT / "agentic_transfer_verifier_extension.py").read_text(encoding="utf-8")
    forbidden = ("requests", "urllib", "socket", "subprocess", "entry_points()", "Path(")
    assert not any(token in source for token in forbidden)


def test_crlf_source_cannot_build_against_lf_bound_manifest(tmp_path: Path) -> None:
    copied = tmp_path / "extension"
    shutil.copytree(EXTENSION_ROOT, copied)
    module = copied / "agentic_transfer_verifier_extension.py"
    module.write_bytes(module.read_bytes().replace(b"\n", b"\r\n"))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(tmp_path / "dist"),
            str(copied),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode != 0
    assert "implementation digest drift" in result.stdout + result.stderr
