"""Command-line interface for skillcheck."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from skillcheck import __version__
from skillcheck.report import (
    exit_code_for,
    report_to_json,
    report_to_text,
)
from skillcheck.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillcheck",
        description="Offline safety linter for agent skill files.",
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="path to a skill file or a repository root (default: current directory)",
    )
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument(
        "--strict",
        action="store_true",
        help="treat 'unknown' verdict as an unsafe exit (exit 2 instead of 1)",
    )
    p.add_argument(
        "--include-info",
        action="store_true",
        help="include INFO-severity findings (SKILLCHECK-009) in output",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"skillcheck {__version__}",
    )
    return p


def main(argv: Optional[List[str]] = None, *, stdout=None, stderr=None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)

    path = args.path
    if not os.path.exists(path):
        stderr.write(f"skillcheck: path does not exist: {path}\n")
        return 2

    report = scan_path(path)
    code = exit_code_for(report, strict=args.strict)

    if args.json:
        stdout.write(report_to_json(report, include_info=args.include_info))
        stdout.write("\n")
        return code

    # docs/CONVENTIONS.md Stdout / stderr discipline: a silent rc=0
    # text-mode run must produce zero bytes on stdout so downstream
    # `jq` / `test -s` / `| head` consumers can rely on empty stdout
    # meaning "nothing to look at". Under skillcheck's Convention C
    # verdict rollup, rc=0 iff verdict=SAFE, so the verdict-and-counts
    # block is diagnostic prose in that case and belongs on stderr;
    # on non-zero rc (SUSPICIOUS/UNSAFE/UNKNOWN incl. --strict) the
    # same block frames actionable findings and stays on stdout so
    # consumers that already scrape stdout for SKILLCHECK-* rule
    # codes are unchanged. `report_to_text()` is unchanged and
    # remains the public formatter API; the routing decision lives
    # in the CLI so a caller that imports it directly still gets a
    # self-contained report string.
    text_output = report_to_text(report, include_info=args.include_info)
    if code == 0:
        stderr.write(text_output)
        stderr.write("\n")
    else:
        stdout.write(text_output)
        stdout.write("\n")

    return code


if __name__ == "__main__":
    raise SystemExit(main())
