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

    if args.json:
        stdout.write(report_to_json(report, include_info=args.include_info))
        stdout.write("\n")
    else:
        stdout.write(report_to_text(report, include_info=args.include_info))
        stdout.write("\n")

    return exit_code_for(report, strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
