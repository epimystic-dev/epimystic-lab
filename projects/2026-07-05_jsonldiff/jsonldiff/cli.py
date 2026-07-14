"""Command-line interface for ``jsonldiff``."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable, Optional, Sequence

from .core import Change, diff_streams


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jsonldiff",
        description=(
            "Semantic diff between two JSONL streams. Records are compared "
            "structurally, with per-path added / removed / changed events, "
            "so ordering and whitespace inside a JSON object no longer "
            "obscures real differences."
        ),
    )
    p.add_argument("baseline", help="Baseline JSONL file.")
    p.add_argument("candidate", help="Candidate JSONL file.")
    p.add_argument(
        "--key",
        default=None,
        metavar="PATH",
        help=(
            "Dotted path used to align records by value instead of by line "
            "position (e.g. 'id' or 'meta.run_id')."
        ),
    )
    p.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "Dotted path to ignore. Repeatable. Matches the exact path OR any "
            "sub-path underneath it."
        ),
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--max-diffs",
        type=int,
        default=None,
        metavar="N",
        help="Stop after N differences (default: report all).",
    )
    p.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit 1 if any differences were found (default: always exit 0).",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the trailing summary line.",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        baseline_f = open(args.baseline, "r", encoding="utf-8", newline="")
    except OSError as exc:
        print(f"jsonldiff: cannot read baseline {args.baseline}: {exc}", file=sys.stderr)
        return 2
    try:
        candidate_f = open(args.candidate, "r", encoding="utf-8", newline="")
    except OSError as exc:
        baseline_f.close()
        print(
            f"jsonldiff: cannot read candidate {args.candidate}: {exc}",
            file=sys.stderr,
        )
        return 2

    diffs = 0
    parse_errors = 0
    try:
        for change in diff_streams(
            baseline_f,
            candidate_f,
            key=args.key,
            ignore=args.ignore,
            max_diffs=args.max_diffs,
        ):
            diffs += 1
            if change.kind.startswith("parse_error"):
                parse_errors += 1
            if args.format == "json":
                print(json.dumps(change.to_json(), ensure_ascii=False))
            else:
                print(_format_text(change))
    finally:
        baseline_f.close()
        candidate_f.close()

    if not args.quiet and args.format == "text":
        _print_summary(diffs, parse_errors)

    if parse_errors:
        return 2
    if args.exit_code and diffs:
        return 1
    return 0


def _format_text(c: Change) -> str:
    header = f"line {c.position}"
    if c.key is not None:
        header += f" key={_pretty(c.key)}"
    if c.kind == "changed":
        return f"  {header}  {c.path}: {_pretty(c.baseline)} -> {_pretty(c.candidate)}"
    if c.kind == "added":
        return f"  {header}  + {c.path}: {_pretty(c.candidate)}"
    if c.kind == "removed":
        return f"  {header}  - {c.path}: {_pretty(c.baseline)}"
    if c.kind == "missing_in_baseline":
        return f"  {header}  MISSING in baseline (candidate: {_pretty(c.candidate)})"
    if c.kind == "missing_in_candidate":
        return f"  {header}  MISSING in candidate (baseline: {_pretty(c.baseline)})"
    if c.kind == "parse_error_baseline":
        return f"  {header}  PARSE ERROR (baseline): {c.baseline}"
    if c.kind == "parse_error_candidate":
        return f"  {header}  PARSE ERROR (candidate): {c.candidate}"
    return f"  {header}  {c.kind}: {c.path}"


def _pretty(value) -> str:
    try:
        s = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        s = repr(value)
    if len(s) > 200:
        s = s[:197] + "..."
    return s


def _print_summary(diffs: int, parse_errors: int) -> None:
    if diffs == 0:
        print("jsonldiff: no differences", file=sys.stderr)
        return
    msg = f"jsonldiff: {diffs} difference(s)"
    if parse_errors:
        msg += f", {parse_errors} parse error(s)"
    print(msg, file=sys.stderr)
