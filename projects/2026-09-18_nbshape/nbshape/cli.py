"""Command-line interface for nbshape."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Sequence

from . import __version__
from .report import format_findings, format_json, format_summary
from .rules import ALL_RULES, RULES_BY_ID, RuleConfig
from .scanner import DEFAULT_GLOBS, DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, scan_path
from .verdict import compute_verdict, exit_code_for


PROG = "nbshape"

_DESCRIPTION = (
    "Reproducibility-hygiene linter for Jupyter notebook JSON. Flags stored-file "
    "shapes - out-of-order execution counters, retained outputs, unseeded sampling, "
    "machine-local paths, credential-shaped literals. It executes nothing and cannot "
    "tell you whether a notebook reproduces."
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=PROG, description=_DESCRIPTION)
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Notebook file or directory to scan (default: current directory).",
    )
    p.add_argument("--version", action="version", version=PROG + " " + __version__)
    p.add_argument("--json", action="store_true",
                   help="Emit the whole report as deterministic JSON on stdout.")
    p.add_argument("--strict", action="store_true",
                   help="Escalate INFO to needs-attention; an unknown verdict exits 2.")
    p.add_argument("--include-info", action="store_true",
                   help="Show INFO findings (hidden by default; always counted).")
    p.add_argument("--disable", action="append", default=[], metavar="CODE",
                   help="Disable one rule, repeatable. Example: --disable NBK-004")
    p.add_argument("--include-checkpoints", action="store_true",
                   help="Also scan .ipynb_checkpoints/ (skipped by default: they are "
                        "near-duplicates and double every count).")
    p.add_argument("--glob", action="append", default=[], metavar="PATTERN",
                   help="Extend the default file-glob set (repeatable).")
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                   help="Cap files scanned per run (default " + str(DEFAULT_MAX_FILES) + ").")
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                   help="Skip any notebook larger than this, reporting it as unknown "
                        "(default " + str(DEFAULT_MAX_BYTES) + ").")
    p.add_argument("--rerun-factor", type=float, default=RuleConfig.rerun_factor,
                   help="NBK-004 fires when max(execution_count) exceeds the code-cell "
                        "count times this factor (default " +
                        ("%g" % RuleConfig.rerun_factor) + ").")
    p.add_argument("--min-literal-len", type=int, default=RuleConfig.min_literal_len,
                   help="NBK-006 minimum string-literal length (default " +
                        str(RuleConfig.min_literal_len) + ").")
    p.add_argument("--max-output-bytes", type=int, default=RuleConfig.max_output_bytes,
                   help="NBK-011 absolute committed-payload threshold (default " +
                        str(RuleConfig.max_output_bytes) + ").")
    p.add_argument("--list-rules", action="store_true",
                   help="Print the rule registry on stdout and exit 0.")
    return p


def _print_rules(stream) -> None:
    for r in ALL_RULES:
        stream.write(r.id + " " + r.severity.value + " " + r.title + "\n")


def main(argv: Optional[Sequence[str]] = None, stdout=None, stderr=None) -> int:
    """Entry point. Returns the process exit code; never raises on bad input."""
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
        stderr.write(PROG + ": --max-files must be greater than 0\n")
        return 2
    if args.max_bytes <= 0:
        stderr.write(PROG + ": --max-bytes must be greater than 0\n")
        return 2
    if args.rerun_factor <= 0:
        stderr.write(PROG + ": --rerun-factor must be greater than 0\n")
        return 2
    if args.min_literal_len <= 0:
        stderr.write(PROG + ": --min-literal-len must be greater than 0\n")
        return 2
    if args.max_output_bytes <= 0:
        stderr.write(PROG + ": --max-output-bytes must be greater than 0\n")
        return 2

    unknown_rules = [d for d in args.disable if d not in RULES_BY_ID]
    if unknown_rules:
        stderr.write(
            PROG + ": unknown rule id(s) for --disable: " + ", ".join(unknown_rules) +
            "; run --list-rules to see the registry\n"
        )
        return 2

    if not os.path.exists(args.path):
        stderr.write(PROG + ": path does not exist: " + args.path + "\n")
        return 2

    config = RuleConfig(
        rerun_factor=args.rerun_factor,
        min_literal_len=args.min_literal_len,
        max_output_bytes=args.max_output_bytes,
    )
    globs = list(DEFAULT_GLOBS) + list(args.glob)

    result = scan_path(
        args.path,
        globs=globs,
        disabled=frozenset(args.disable),
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        include_checkpoints=args.include_checkpoints,
        config=config,
    )

    if args.json:
        stdout.write(format_json(result, strict=args.strict, include_info=args.include_info))
    else:
        text = format_findings(result, include_info=args.include_info)
        if text:
            stdout.write(text)
    stderr.write(format_summary(result, strict=args.strict, include_info=args.include_info))

    verdict = compute_verdict(result, strict=args.strict)
    return exit_code_for(verdict, strict=args.strict)
