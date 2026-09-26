from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from agentic_transfer_verifier import EnvelopeInputError, load_json_envelope
from agentic_transfer_verifier.cli import main, render_report
from agentic_transfer_verifier.models import Finding, VerificationReport

ROOT = Path(__file__).resolve().parents[1]


def _valid() -> dict:
    return json.loads((ROOT / "examples" / "tool-output.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["tool-output", "memory-write", "approval", "ocr-transcript"])
def test_examples_are_valid_and_pass(name: str) -> None:
    from agentic_transfer_verifier import verify_envelope

    envelope = load_json_envelope((ROOT / "examples" / f"{name}.json").read_bytes())
    assert verify_envelope(envelope).status == "PASS"


@pytest.mark.parametrize("raw", [
    b'{"envelope_id":"a","envelope_id":"b"}',
    b'{"x":{"a":1,"a":2}}',
    b'{"x":NaN}',
    b'{"x":1e999}',
    b'\xff',
    b'{"x":"\\ud800"}',
    b'[]',
    b' ' * 65_537,
], ids=["duplicate-top", "duplicate-nested", "nan", "overflow", "utf8", "surrogate",
        "non-object", "size"])
def test_loader_rejects_invalid_json_and_bounds(raw: bytes) -> None:
    with pytest.raises(EnvelopeInputError):
        load_json_envelope(raw)


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(unknown=True),
    lambda d: d.update(trust_level="superuser"),
    lambda d: d.update(authority_scope=True),
    lambda d: d.update(consumed_as=3),
    lambda d: d.update(payload=[]),
    lambda d: d.update(provenance=[{"actor": "a", "action": "b", "source": "c", "x": 1}]),
    lambda d: d.update(provenance=[{"actor": "a", "action": "b", "source": False}]),
    lambda d: d.update(identity_claims=[{"subject": "a", "verified": 1}]),
    lambda d: d.update(capabilities=[{"name": "a", "scope": "invalid"}]),
    lambda d: d.update(allowed_uses=[True]),
])
def test_loader_rejects_model_mismatch(mutate) -> None:
    data = _valid()
    mutate(data)
    with pytest.raises(EnvelopeInputError):
        load_json_envelope(json.dumps(data).encode())


@pytest.mark.parametrize("levels,accepted", [(61, True), (62, False)])
def test_payload_depth_boundary(levels: int, accepted: bool) -> None:
    data = _valid()
    nested: object = 0
    for _ in range(levels):
        nested = [nested]
    data["payload"] = {"nested": nested}
    raw = json.dumps(data).encode()
    if accepted:
        assert load_json_envelope(raw).payload == data["payload"]
    else:
        with pytest.raises(EnvelopeInputError, match="nesting limit"):
            load_json_envelope(raw)


@pytest.mark.parametrize("field", ["provenance", "allowed_uses"])
def test_declared_list_limit(field: str) -> None:
    data = _valid()
    item = data[field][0] if field == "provenance" else "synthetic-use"
    data[field] = [item] * 65
    with pytest.raises(EnvelopeInputError, match="bounded list"):
        load_json_envelope(json.dumps(data).encode())


def test_very_large_integer_is_input_error() -> None:
    data = _valid()
    data["payload"] = {"number": 0}
    raw = json.dumps(data).encode().replace(b'"number": 0', b'"number": ' + b'9' * 5000)
    with pytest.raises(EnvelopeInputError):
        load_json_envelope(raw)


def test_integer_limit_is_owned_by_loader_not_python_setting() -> None:
    from agentic_transfer_verifier.json_envelope import MAX_INTEGER_DIGITS

    data = _valid()
    data["payload"] = {"number": 0}
    raw = json.dumps(data).encode().replace(
        b'"number": 0', b'"number": ' + b'9' * (MAX_INTEGER_DIGITS + 1)
    )
    with pytest.raises(EnvelopeInputError, match="integer digit limit"):
        load_json_envelope(raw)
    data["payload"]["number"] = int("9" * MAX_INTEGER_DIGITS)
    assert load_json_envelope(json.dumps(data).encode()).payload == data["payload"]


def test_valid_structural_failure_is_a_report(tmp_path: Path, capsys) -> None:
    data = _valid()
    data["provenance"] = []
    source = tmp_path / "input.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify", str(source)]) == 2
    assert json.loads(capsys.readouterr().out)["findings"][0]["code"] == "missing_provenance"


def test_malformed_input_never_invokes_verifier(tmp_path: Path, capsys, monkeypatch) -> None:
    source = tmp_path / "input.json"
    source.write_bytes(b'{"payload":"private marker"}')
    monkeypatch.setattr(
        "agentic_transfer_verifier.cli.verify_envelope", lambda _: pytest.fail("called")
    )
    assert main(["verify", str(source)]) == 3
    output = capsys.readouterr()
    assert "private marker" not in output.err + output.out
    assert not output.out


def test_markdown_escapes_identifier_and_omits_payload() -> None:
    report = VerificationReport(
        envelope_id="<img src=x>|\n#bad [link](url)", status="FAIL",
        findings=[Finding(code="synthetic", severity="high", message="Fixed finding")],
    )
    rendered = render_report(report, "markdown")
    assert "<img" not in rendered
    assert "&#10;" in rendered
    assert "\\|" in rendered
    assert "\\#bad" in rendered


def test_output_is_exclusive_without_overwrite(tmp_path: Path, capsys) -> None:
    source = ROOT / "examples" / "tool-output.json"
    output = tmp_path / "report.json"
    output.write_text("prior", encoding="utf-8")
    assert main(["verify", str(source), "--output", str(output)]) == 4
    assert output.read_text(encoding="utf-8") == "prior"
    assert main(["verify", str(source), "--output", str(output), "--overwrite"]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "PASS"
    assert "report I/O error" in capsys.readouterr().err


def test_output_cannot_replace_input_even_with_overwrite(tmp_path: Path, capsys) -> None:
    source = tmp_path / "input.json"
    original = (ROOT / "examples" / "tool-output.json").read_bytes()
    source.write_bytes(original)
    assert main(["verify", str(source), "--output", str(source), "--overwrite"]) == 4
    assert source.read_bytes() == original
    assert "report output must differ from input" in capsys.readouterr().err


def test_stdin_fixture_succeeds(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    raw = (ROOT / "examples" / "tool-output.json").read_bytes()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8"))
    assert main(["verify", "-"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"


def test_ascii_stdout_encoding_failure_is_content_free(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    data = _valid()
    data["envelope_id"] = "synthetic-\u00e9-marker"
    raw = json.dumps(data).encode()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8"))
    stdout = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
    monkeypatch.setattr(sys, "stdout", stdout)
    assert main(["verify", "-", "--format", "markdown"]) == 4
    assert stdout.buffer.getvalue() == b""
    diagnostic = capsys.readouterr().err
    assert diagnostic == "report I/O error\n"
    assert "synthetic" not in diagnostic


def test_warn_markdown_and_missing_file_exit_codes(tmp_path: Path, capsys) -> None:
    data = _valid()
    data["consumer"] = data["producer"]
    source = tmp_path / "warning.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify", str(source), "--format", "markdown"]) == 1
    assert "Status: **WARN**" in capsys.readouterr().out
    assert main(["verify", str(tmp_path / "absent.json")]) == 4
    assert "input I/O error" in capsys.readouterr().err


def test_json_report_deterministic_and_payload_free(tmp_path: Path, capsys) -> None:
    data = _valid()
    data["payload"] = {"private": "synthetic-payload-marker"}
    source = tmp_path / "input.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify", str(source)]) == 0
    first = capsys.readouterr().out
    assert main(["verify", str(source)]) == 0
    assert capsys.readouterr().out == first
    assert "synthetic-payload-marker" not in first
