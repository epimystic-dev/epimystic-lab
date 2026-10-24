"""Command-line interface for reqcheck."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Iterable, List, Sequence, TextIO

from . import __version__
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


CLEAN_TEXT_SUMMARY = "no findings\n"


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the package names REQ-A007
      exists to flag are made of exactly those characters (as can be the
      path of the requirements file). Echoing them raw crashed the reporter
      mid-write, so the most dangerous inputs produced a traceback and no
      finding at all.
    * A concealed character must be made visible in the report, not echoed
      raw and so concealed a second time in the very output meant to expose
      it.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if 32 <= cp < 127:
            out.append(ch)
        else:
            out.append("<U+%04X>" % cp)
    return "".join(out)


def _format_text(findings: Sequence[Finding]) -> str:
    # The clean-run "no findings" summary is emitted by the caller to
    # stderr per docs/CONVENTIONS.md Stdout / stderr discipline; keeping
    # it out of this formatter is what lets a silent rc=0 text-mode run
    # produce a 0-byte stdout that `jq` / `test -s` consumers can rely on.
    if not findings:
        return ""
    lines = []
    for f in findings:
        lines.append(
            f"{f.file}:{f.location.line}: {f.severity.upper()} {f.rule}: {f.message}"
        )
        if f.suggestion:
            lines.append(f"    suggestion: {f.suggestion}")
    # Each line is one record; a newline inside a path, name or message is
    # rendered as <U+000A> rather than starting a forged line of its own.
    return "\n".join(_visible(line) for line in lines) + "\n"


def _format_json(
    findings: Sequence[Finding],
    *,
    source: str,
    files_scanned: int,
) -> str:
    # Top-level wrapping shape documented in docs/CONVENTIONS.md Structured
    # output: `{tool, version, source, findings, summary}`. Pre-0.3.0 reqcheck
    # emitted a bare `findings` array; the wrapping is the breaking change the
    # version bump marks. `by_severity` keys match the Finding.severity values
    # the per-finding records already carry (`error` / `warn` / `info`), so a
    # consumer reading `summary.by_severity.error` sees the same term it would
    # see on each record under `severity`.
    by_severity = {"error": 0, "warn": 0, "info": 0}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    payload = {
        "tool": "reqcheck",
        "version": __version__,
        "source": source,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total_findings": len(findings),
            "files_scanned": files_scanned,
            "by_severity": by_severity,
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


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


def _read_stdin_findings(include_info: bool, strict: bool) -> List[Finding]:
    # Returns the findings for stdin; the caller handles output so that a
    # mixed stdin + file-path invocation produces a single JSON wrapping
    # object rather than two concatenated payloads.
    text = sys.stdin.read()
    pf = parse_text(text, path="<stdin>")
    findings = audit_parsed(pf, include_info=include_info)
    if strict:
        findings = _apply_strict(findings)
    return findings


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
        "--version",
        action="version",
        version=f"reqcheck {__version__}",
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
        "--json",
        action="store_true",
        help=(
            "Shortcut for --format json. Preferred flag; --format json is "
            "retained for compatibility."
        ),
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
    if args.json:
        args.format = "json"

    all_findings: List[Finding] = []
    sources: List[str] = []
    files_scanned = 0
    exit_code = EXIT_CLEAN
    for path in args.paths:
        if path == "-":
            findings = _read_stdin_findings(args.include_info, args.strict)
            all_findings.extend(findings)
            sources.append("<stdin>")
            files_scanned += 1
            continue
        # os.path.isdir short-circuit: on Windows, open() of a directory
        # raises PermissionError (not IsADirectoryError), so a POSIX-only
        # IsADirectoryError catch would leak a traceback on Windows.
        if os.path.isdir(path):
            stderr.write(f"reqcheck: is a directory: {path}\n")
            exit_code = max(exit_code, EXIT_ERROR)
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
        except PermissionError:
            stderr.write(f"reqcheck: permission denied: {path}\n")
            exit_code = max(exit_code, EXIT_ERROR)
            continue
        except UnicodeDecodeError as e:
            stderr.write(
                f"reqcheck: not valid UTF-8: {path} "
                f"(byte {e.start}: {e.reason})\n"
            )
            exit_code = max(exit_code, EXIT_ERROR)
            continue
        if args.strict:
            findings = _apply_strict(findings)
        all_findings.extend(findings)
        sources.append(path)
        files_scanned += 1

    source_str = ",".join(sources)
    if args.format == "json":
        stdout.write(
            _format_json(
                all_findings,
                source=source_str,
                files_scanned=files_scanned,
            )
        )
    elif all_findings:
        stdout.write(_format_text(all_findings))
    else:
        stderr.write(CLEAN_TEXT_SUMMARY)

    exit_code = max(exit_code, _severity_of(all_findings))
    return exit_code
