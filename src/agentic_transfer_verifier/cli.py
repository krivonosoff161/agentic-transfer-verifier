"""Offline, read-only command for checking one local transfer envelope."""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

from agentic_transfer_verifier.json_envelope import (
    MAX_ENVELOPE_BYTES,
    EnvelopeInputError,
    load_json_envelope,
)
from agentic_transfer_verifier.models import VerificationReport
from agentic_transfer_verifier.verifier import verify_envelope


def _markdown_text(value: str) -> str:
    escaped = html.escape(value, quote=True)
    return "".join(
        f"&#{ord(char)};" if ord(char) < 32 or ord(char) == 127 else
        "\\" + char if char in "\\`*_{}[]()#+-.!|>" else char
        for char in escaped
    )


def render_report(report: VerificationReport, format: str) -> str:
    """Render only the verifier's report, never the original payload."""

    if format == "json":
        return json.dumps(report.to_dict(), ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    if format != "markdown":
        raise ValueError("unsupported report format")
    lines = [
        "# Transfer verification report", "",
        f"Envelope ID: {_markdown_text(report.envelope_id)}", "",
        f"Status: **{report.status}**", "",
        "| Severity | Code | Finding |", "| --- | --- | --- |",
    ]
    for finding in report.findings:
        lines.append(
            f"| {_markdown_text(finding.severity)} | {_markdown_text(finding.code)} "
            f"| {_markdown_text(finding.message)} |"
        )
    if not report.findings:
        lines.append("| — | — | No findings |")
    return "\n".join(lines) + "\n"


def _read_input(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read(MAX_ENVELOPE_BYTES + 1)
    with Path(path).open("rb") as stream:
        return stream.read(MAX_ENVELOPE_BYTES + 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentic-transfer-verifier")
    command = parser.add_subparsers(dest="command", required=True)
    verify = command.add_parser("verify", help="verify one local JSON envelope")
    verify.add_argument("input", help="local JSON path, or - for standard input")
    verify.add_argument("--format", choices=("json", "markdown"), default="json")
    verify.add_argument("--output", type=Path, help="report path; default is standard output")
    verify.add_argument("--overwrite", action="store_true", help="explicitly replace report path")
    args = parser.parse_args(argv)
    if args.overwrite and args.output is None:
        parser.error("--overwrite requires --output")
    try:
        raw = _read_input(args.input)
    except OSError:
        print("input I/O error", file=sys.stderr)
        return 4
    try:
        envelope = load_json_envelope(raw)
    except EnvelopeInputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 3
    report = verify_envelope(envelope)
    rendered = render_report(report, args.format)
    try:
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            if args.input != "-" and args.output.exists() and args.output.samefile(args.input):
                print("report output must differ from input", file=sys.stderr)
                return 4
            with args.output.open(
                "w" if args.overwrite else "x", encoding="utf-8", newline="\n"
            ) as stream:
                stream.write(rendered)
    except (OSError, UnicodeError):
        print("report I/O error", file=sys.stderr)
        return 4
    return {"PASS": 0, "WARN": 1, "FAIL": 2}[report.status]


if __name__ == "__main__":
    raise SystemExit(main())
