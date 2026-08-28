"""Small deterministic PEP 517 backend for the closed single-module extension wheel."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

NAME = "agentic-transfer-verifier-harness-extension"
NORMALIZED = "agentic_transfer_verifier_harness_extension"
VERSION = "1.0.0"
MODULE = "agentic_transfer_verifier_extension.py"
MANIFEST = "ash-extension-manifest.json"
CONFIGURATION = "configuration.json"
DIST_INFO = f"{NORMALIZED}-{VERSION}.dist-info"
WHEEL_NAME = f"{NORMALIZED}-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"{NAME}-{VERSION}.tar.gz"
ROOT = Path(__file__).resolve().parent
MAX_SOURCE_BYTES = 1_048_576


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    del config_settings, metadata_directory
    output = Path(wheel_directory)
    output.mkdir(parents=True, exist_ok=True)
    files = _wheel_files()
    record_path = f"{DIST_INFO}/RECORD"
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for path in sorted(files):
        payload = files[path]
        writer.writerow((path, _record_digest(payload), len(payload)))
    writer.writerow((record_path, "", ""))
    files[record_path] = record.getvalue().encode("utf-8")
    destination = output / WHEEL_NAME
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[path])
    return WHEEL_NAME


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    del config_settings
    target = Path(metadata_directory) / DIST_INFO
    target.mkdir(parents=True, exist_ok=True)
    files = _wheel_files()
    for name in ("METADATA", "WHEEL", "entry_points.txt", MANIFEST):
        (target / name).write_bytes(files[f"{DIST_INFO}/{name}"])
    return DIST_INFO


def build_sdist(
    sdist_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    del config_settings
    output = Path(sdist_directory)
    output.mkdir(parents=True, exist_ok=True)
    source_files = {
        "PKG-INFO": _metadata_bytes(),
        "README.md": _read_source("README.md"),
        "pyproject.toml": _read_source("pyproject.toml"),
        "backend.py": _read_source("backend.py"),
        MODULE: _read_source(MODULE),
        CONFIGURATION: _read_source(CONFIGURATION),
        MANIFEST: _read_source(MANIFEST),
    }
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        for name in sorted(source_files):
            content = source_files[name]
            info = tarfile.TarInfo(f"{NAME}-{VERSION}/{name}")
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    destination = output / SDIST_NAME
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            compressed.write(payload.getvalue())
    return SDIST_NAME


def _wheel_files() -> dict[str, bytes]:
    module = _read_source(MODULE)
    manifest = _read_source(MANIFEST)
    configuration = _read_source(CONFIGURATION)
    _validate_manifest(manifest, module, configuration)
    return {
        MODULE: module,
        f"{DIST_INFO}/METADATA": _metadata_bytes(),
        f"{DIST_INFO}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: agentic-transfer-verifier-extension-backend\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{DIST_INFO}/entry_points.txt": (
            b"[agentic_security_harness.extensions.v1]\n"
            b"agentic-transfer-verifier.verification = "
            b"agentic_transfer_verifier_extension:build_extension\n"
        ),
        f"{DIST_INFO}/{MANIFEST}": manifest,
    }


def _metadata_bytes() -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        f"Name: {NAME}\n"
        f"Version: {VERSION}\n"
        "Summary: Operator-approved digest-only Harness extension for Transfer Verifier.\n"
        "Requires-Python: >=3.11,<3.14\n"
        "License-Expression: MIT\n"
        "\n"
    ).encode()


def _validate_manifest(payload: bytes, module: bytes, configuration: bytes) -> None:
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("extension manifest is not valid UTF-8 JSON") from exc
    canonical = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if canonical != payload:
        raise RuntimeError("extension manifest is not canonical JSON")
    if value.get("implementation_sha256") != hashlib.sha256(module).hexdigest():
        raise RuntimeError("extension manifest implementation digest drift")
    if value.get("configuration_sha256") != hashlib.sha256(configuration).hexdigest():
        raise RuntimeError("extension manifest configuration digest drift")


def _read_source(name: str) -> bytes:
    if PurePosixPath(name).name != name:
        raise RuntimeError("extension source name is not canonical")
    path = ROOT / name
    payload = path.read_bytes()
    if not payload or len(payload) > MAX_SOURCE_BYTES:
        raise RuntimeError("extension source file size is outside the build contract")
    return payload


def _record_digest(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode("ascii")
    return f"sha256={encoded.rstrip('=')}"
