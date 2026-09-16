"""Command-line interface for delegcheck."""

import argparse
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .rules import ALL_RULES
from .report import format_json, format_text
from .scanner import (
    DEFAULT_GLOBS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    scan_path,
)
from .verdict import compute_verdict, exit_code_for


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="delegcheck",
        description=(
            "Offline static linter for agent-delegation configuration files "
            "(MCP-style server descriptors, agent manifests, tool registries)."
        ),
    )
    p.add_argument("path", nargs="?", default=".", help="Directory or file (default: current directory).")
    p.add_argument("--version", action="version", version="delegcheck " + __version__)
    p.add_argument("--json", action="store_true", help="Emit findings as deterministic JSON.")
    p.add_argument("--strict", action="store_true",
                   help="Escalate INFO to needs-attention; no-files to exit 2.")
    p.add_argument("--include-info", action="store_true",
                   help="Include INFO findings in text/JSON output (always counted).")
    p.add_argument("--disable", action="append", default=[], metavar="RULE_ID",
                   help="Disable a rule (repeatable). Example: --disable DEL-010")
    p.add_argument("--glob", action="append", default=[], metavar="PATTERN",
                   help="Extend the default file-glob set (repeatable).")
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                   help="Cap files scanned per run (default " + str(DEFAULT_MAX_FILES) + ").")
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                   help="Cap bytes read per file (default " + str(DEFAULT_MAX_BYTES) + ").")
    p.add_argument("--list-rules", action="store_true",
                   help="Print the rule registry and exit.")
    return p


def _print_rules(stream) -> None:
    for r in ALL_RULES:
        stream.write(r.id + " " + r.severity.value + " " + r.description + "\n")


def main(argv: Optional[Sequence[str]] = None,
         stdout=None, stderr=None) -> int:
    if stdout is None:
        stdout = sys.stdout
    if stderr is None:
        stderr = sys.stderr
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list_rules:
        _print_rules(stdout)
        return 0

    if args.max_files <= 0:
        stderr.write("delegcheck: --max-files must be > 0\n")
        return 2
    if args.max_bytes <= 0:
        stderr.write("delegcheck: --max-bytes must be > 0\n")
        return 2

    if not os.path.exists(args.path):
        stderr.write("delegcheck: path does not exist: " + args.path + "\n")
        return 2

    globs = list(DEFAULT_GLOBS) + list(args.glob)
    disabled = frozenset(args.disable)

    result = scan_path(
        args.path,
        globs=globs,
        disabled=disabled,
        max_files=args.max_files,
        max_bytes=args.max_bytes,
    )

    if args.json:
        stdout.write(format_json(result, strict=args.strict, include_info=args.include_info))
    else:
        stdout.write(format_text(result, strict=args.strict, include_info=args.include_info))

    verdict = compute_verdict(result, strict=args.strict)
    return exit_code_for(verdict, strict=args.strict)
