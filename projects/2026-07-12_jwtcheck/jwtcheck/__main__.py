"""jwtcheck CLI.

Usage:
    jwtcheck [options] <path>...

Exit codes:
    0  no findings (or only info)
    1  warnings but no errors
    2  errors found (or unrecoverable I/O)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Sequence

from jwtcheck import __version__
from jwtcheck.audit import Finding, audit_file

_EXIT_OK = 0
_EXIT_WARN = 1
_EXIT_ERROR = 2


def _regex_arg(value: str) -> str:
    """argparse type= for --extra-secret-key: rejects invalid regexes with a
    clean error instead of letting `re.PatternError` traceback out of the CLI."""
    try:
        re.compile(value)
    except re.error as exc:
        raise argparse.ArgumentTypeError(
            f"invalid regex {value!r}: {exc}"
        )
    return value


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jwtcheck",
        description=(
            "JWT / auth-secret hygiene linter for .env files. "
            "Reports weak defaults, empty secrets, placeholder patterns, "
            "low-entropy values, alg=none, and HMAC-key-too-short."
        ),
    )
    p.add_argument(
        "paths",
        nargs="+",
        help=".env file(s) to audit",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format (default: text)",
    )
    p.add_argument(
        "--extra-secret-key",
        action="append",
        default=[],
        metavar="REGEX",
        type=_regex_arg,
        help=(
            "additional regex pattern for keys that should be treated as JWT "
            "secrets; may be given multiple times"
        ),
    )
    p.add_argument(
        "--severity",
        choices=("error", "warn"),
        default="warn",
        help="minimum severity to report (default: warn)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"jwtcheck {__version__}",
    )
    return p


def _filter(findings: Sequence[Finding], min_severity: str) -> List[Finding]:
    if min_severity == "warn":
        return list(findings)
    # min_severity == "error"
    return [f for f in findings if f.severity == "error"]


def _emit_text(findings: Sequence[Finding], stream) -> None:
    for f in findings:
        src = f.source or "-"
        stream.write(
            f"{src}:{f.line}:{f.col}: {f.severity}: {f.rule}: {f.message}\n"
        )


def _emit_json(findings: Sequence[Finding], stream) -> None:
    payload = [
        {
            "rule": f.rule,
            "severity": f.severity,
            "message": f.message,
            "key": f.key,
            "line": f.line,
            "col": f.col,
            "source": f.source,
        }
        for f in findings
    ]
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def run(argv: Sequence[str], stdout=None, stderr=None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr

    ns = _build_parser().parse_args(argv)

    all_findings: List[Finding] = []
    io_error = False

    for raw in ns.paths:
        p = Path(raw)
        if not p.exists():
            stderr.write(f"jwtcheck: {p}: no such file\n")
            io_error = True
            continue
        if p.is_dir():
            stderr.write(f"jwtcheck: {p}: is a directory (pass a file path)\n")
            io_error = True
            continue
        try:
            findings = audit_file(p, extra_secret_keys=ns.extra_secret_key)
        except OSError as exc:
            stderr.write(f"jwtcheck: {p}: {exc}\n")
            io_error = True
            continue
        all_findings.extend(findings)

    filtered = _filter(all_findings, ns.severity)

    if ns.format == "text":
        _emit_text(filtered, stdout)
    else:
        _emit_json(filtered, stdout)

    if io_error:
        return _EXIT_ERROR
    if any(f.severity == "error" for f in all_findings):
        return _EXIT_ERROR
    if any(f.severity == "warn" for f in all_findings):
        return _EXIT_WARN
    return _EXIT_OK


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
