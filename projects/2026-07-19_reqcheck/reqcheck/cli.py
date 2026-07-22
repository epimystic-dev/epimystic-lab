"""Command-line interface for reqcheck."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable, List, Sequence, TextIO

from .model import Finding
from .parser import parse_text
from .rules import audit_file, audit_parsed


EXIT_CLEAN = 0
EXIT_WARN = 1
EXIT_ERROR = 2


def _severity_of(findings: Iterable[Finding]) -> int:
    worst = EXIT_CLEAN
    for f in findings:
        if f.severity == "error":
            return EXIT_ERROR
        if f.severity in ("warn", "info"):
            worst = max(worst, EXIT_WARN)
    return worst


def _format_text(findings: Sequence[Finding]) -> str:
    if not findings:
        return "no findings\n"
    lines = []
    for f in findings:
        lines.append(
            f"{f.file}:{f.location.line}: {f.severity.upper()} {f.rule}: {f.message}"
        )
        if f.suggestion:
            lines.append(f"    suggestion: {f.suggestion}")
    return "\n".join(lines) + "\n"


def _format_json(findings: Sequence[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, sort_keys=True) + "\n"


def _apply_strict(findings: List[Finding]) -> List[Finding]:
    upgraded = []
    for f in findings:
        if f.severity == "warn":
            upgraded.append(
                Finding(
                    rule=f.rule,
                    severity="error",
                    message=f.message,
                    location=f.location,
                    file=f.file,
                    name=f.name,
                    suggestion=f.suggestion,
                )
            )
        else:
            upgraded.append(f)
    return upgraded


def _read_stdin_findings(fmt: str, include_info: bool, strict: bool,
                        stdout: TextIO) -> int:
    text = sys.stdin.read()
    pf = parse_text(text, path="<stdin>")
    findings = audit_parsed(pf, include_info=include_info)
    if strict:
        findings = _apply_strict(findings)
    out = _format_json(findings) if fmt == "json" else _format_text(findings)
    stdout.write(out)
    return _severity_of(findings)


def main(argv: Sequence[str] | None = None,
         stdout: TextIO | None = None,
         stderr: TextIO | None = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr

    parser = argparse.ArgumentParser(
        prog="reqcheck",
        description=(
            "Offline hygiene linter for pip-style requirements files. "
            "Reports supply-chain and reproducibility risks."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="requirements file paths, or '-' for stdin",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as errors (exit 2 on any warning)",
    )
    parser.add_argument(
        "--include-info",
        action="store_true",
        help="include informational findings (REQ-A009)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    all_findings: List[Finding] = []
    exit_code = EXIT_CLEAN
    for path in args.paths:
        if path == "-":
            code = _read_stdin_findings(
                args.format, args.include_info, args.strict, stdout
            )
            exit_code = max(exit_code, code)
            continue
        try:
            pf, findings = audit_file(path, include_info=args.include_info)
        except FileNotFoundError:
            stderr.write(f"reqcheck: no such file: {path}\n")
            exit_code = max(exit_code, EXIT_ERROR)
            continue
        except IsADirectoryError:
            stderr.write(f"reqcheck: is a directory: {path}\n")
            exit_code = max(exit_code, EXIT_ERROR)
            continue
        if args.strict:
            findings = _apply_strict(findings)
        all_findings.extend(findings)

    if args.format == "json":
        stdout.write(_format_json(all_findings))
    else:
        stdout.write(_format_text(all_findings))

    exit_code = max(exit_code, _severity_of(all_findings))
    return exit_code
