"""Validate built archives and smoke the installed transfer-verifier contract."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_MEMBERS = 512
MAX_ARCHIVE_MEMBER_BYTES = 4_194_304
MAX_ARCHIVE_TOTAL_BYTES = 16_777_216
MAX_ARTIFACT_BYTES = 33_554_432
REQUIRED_WHEEL_PATHS = {
    "agentic_transfer_verifier/__init__.py",
    "agentic_transfer_verifier/portfolio_adapter.py",
    "agentic_transfer_verifier/verifier.py",
}
REQUIRED_SDIST_PATHS = {
    ".github/workflows/tests.yml",
    "AGENTS.md",
    "component.yaml",
    "contracts/portfolio-observation.v1.owner-pin.json",
    "docs/package-ci.md",
    "tests/test_package_quality_tools.py",
    "tests/test_portfolio_adapter.py",
    "tools/package_smoke.py",
    "tools/secret_hygiene.py",
}


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return (
        not path.is_absolute()
        and bool(path.parts)
        and ".." not in path.parts
        and not any(":" in part for part in path.parts)
    )


def _validate_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if not 1 <= len(members) <= MAX_ARCHIVE_MEMBERS:
            raise ValueError("wheel member count is outside the supported bound")
        total = 0
        for member in members:
            if not _safe_member(member.filename):
                raise ValueError("wheel contains an unsafe member path")
            if stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError("wheel contains a link member")
            if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ValueError("wheel member exceeds the supported size bound")
            total += member.file_size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise ValueError("wheel exceeds the supported expanded size bound")
        names = {member.filename for member in members}
        if not REQUIRED_WHEEL_PATHS <= names:
            raise ValueError("wheel is missing required package modules")
        if not any(name.endswith(".dist-info/METADATA") for name in names):
            raise ValueError("wheel is missing distribution metadata")


def _validate_sdist(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_ARCHIVE_MEMBERS:
            raise ValueError("sdist member count is outside the supported bound")
        total = 0
        names: set[PurePosixPath] = set()
        for member in members:
            if not _safe_member(member.name):
                raise ValueError("sdist contains an unsafe member path")
            if not (member.isfile() or member.isdir()):
                raise ValueError("sdist contains a non-file member")
            if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ValueError("sdist member exceeds the supported size bound")
            total += member.size
            names.add(PurePosixPath(member.name))
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise ValueError("sdist exceeds the supported expanded size bound")
        roots = {name.parts[0] for name in names if name.parts}
        if len(roots) != 1:
            raise ValueError("sdist must contain one top-level directory")
        root = next(iter(roots))
        relative = {
            PurePosixPath(*name.parts[1:]).as_posix()
            for name in names
            if name.parts and name.parts[0] == root and len(name.parts) > 1
        }
        if not REQUIRED_SDIST_PATHS <= relative:
            raise ValueError("sdist is missing required review or contract files")


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _extract_sdist(sdist: Path, destination: Path) -> Path:
    with tarfile.open(sdist, mode="r:gz") as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_ARCHIVE_MEMBERS:
            raise ValueError("sdist member count is outside the supported bound")
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise ValueError("sdist must contain one top-level directory")
        total = 0
        for member in members:
            relative = PurePosixPath(member.name)
            if not _safe_member(member.name):
                raise ValueError("sdist contains an unsafe member path")
            if member.size > MAX_ARCHIVE_MEMBER_BYTES:
                raise ValueError("sdist member exceeds the supported size bound")
            total += member.size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise ValueError("sdist exceeds the supported expanded size bound")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError("sdist contains a non-file member")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("sdist file member cannot be read")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=65_536)
        return destination / next(iter(roots))


def _snapshot_artifact(source: Path, destination: Path) -> Path:
    before = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise ValueError("distribution artifact must be a regular file")
    if not 1 <= before.st_size <= MAX_ARTIFACT_BYTES:
        raise ValueError("distribution artifact size is outside the supported bound")
    with source.open("rb") as stream:
        first = stream.read(MAX_ARTIFACT_BYTES + 1)
    with source.open("rb") as stream:
        second = stream.read(MAX_ARTIFACT_BYTES + 1)
    after = source.lstat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if (
        len(first) > MAX_ARTIFACT_BYTES
        or identity_before != identity_after
        or first != second
        or len(first) != before.st_size
    ):
        raise ValueError("distribution artifact changed during snapshot")
    destination.write_bytes(first)
    return destination


def _sdist_test(sdist: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="transfer-verifier-sdist-") as raw:
        root = _extract_sdist(sdist, Path(raw))
        clean_env = os.environ.copy()
        clean_env["PYTHONPATH"] = str(root / "src")
        clean_env.pop("PYTHONHOME", None)
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
            check=True,
            cwd=root,
            env=clean_env,
            timeout=120,
        )


def _installed_smoke(wheel: Path, expected_version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="transfer-verifier-wheel-") as raw:
        root = Path(raw)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        python = _venv_python(environment)
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-index",
                str(wheel.resolve()),
            ],
            check=True,
            cwd=root,
            timeout=120,
        )
        probe = (
            "import importlib.metadata as metadata; "
            "from agentic_transfer_verifier import ProvenanceStep, TransferEnvelope, "
            "verify_envelope, __version__; "
            f"expected={expected_version!r}; "
            "assert metadata.version('agentic-transfer-verifier') == expected; "
            "assert __version__ == expected; "
            "envelope=TransferEnvelope(envelope_id='synthetic-smoke', "
            "producer='agent-a', consumer='agent-b', payload_kind='summary', "
            "trust_level='untrusted', authority_scope='none', "
            "payload={'synthetic': True}, "
            "provenance=[ProvenanceStep(actor='operator', action='created', "
            "source='local-fixture')]); "
            "report=verify_envelope(envelope); "
            "assert report.status == 'PASS'; "
            "assert report.envelope_id == 'synthetic-smoke'"
        )
        clean_env = os.environ.copy()
        clean_env.pop("PYTHONPATH", None)
        clean_env.pop("PYTHONHOME", None)
        subprocess.run(
            [str(python), "-I", "-c", probe],
            check=True,
            cwd=root,
            env=clean_env,
            timeout=60,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    wheels = sorted(args.dist_dir.glob("*.whl"))
    sdists = sorted(args.dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("expected exactly one wheel and one sdist")
    with tempfile.TemporaryDirectory(prefix="transfer-verifier-artifacts-") as raw:
        root = Path(raw)
        wheel = _snapshot_artifact(wheels[0], root / wheels[0].name)
        sdist = _snapshot_artifact(sdists[0], root / sdists[0].name)
        _validate_wheel(wheel)
        _validate_sdist(sdist)
        _sdist_test(sdist)
        _installed_smoke(wheel, args.expected_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
