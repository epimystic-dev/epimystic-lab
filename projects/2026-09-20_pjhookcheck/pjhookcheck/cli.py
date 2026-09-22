"""Command-line entrypoint."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence, TextIO

from . import __version__
from .report import render_json, render_text
from .rules import REGISTRY, REGISTRY_BY_ID, all_rule_ids
from .scanner import scan_paths
from .types import Options, Severity
from .verdict import compute_verdict, exit_code


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pjhookcheck",
        description=(
            "Static linter for package.json lifecycle-hook and "
            "install-time supply-chain shapes. Zero dependencies."
        ),
    )
    p.add_argument(
        "paths", nargs="*",
        help="One or more .json files or directories. "
             "Directories are walked for package.json.",
    )
    p.add_argument("--json", action="store_true",
                   help="Emit the structured report on stdout instead of text.")
    p.add_argument("--strict", action="store_true",
                   help="Escalate INFO findings to unhealthy; "
                        "no files scanned becomes rc 2.")
    p.add_argument("--include-info", action="store_true",
                   help="Show INFO findings (hidden by default).")
    p.add_argument("--disable", action="append", default=[], metavar="RULE",
                   help="Disable one rule id (repeatable).")
    p.add_argument("--list-rules", action="store_true",
                   help="Print the rule registry and exit 0.")
    p.add_argument("--glob", action="append", default=[],
                   help="Extra glob pattern to include when walking "
                        "directories (repeatable).")
    p.add_argument("--max-files", type=int, default=5000,
                   help="Upper bound on files scanned (default 5000).")
    p.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024,
                   help="Per-file byte cap (default 5 MiB).")
    p.add_argument("--version", action="store_true",
                   help="Print the version and exit 0.")
    return p


def _list_rules(out: TextIO) -> int:
    for r in REGISTRY:
        out.write(f"{r.id}  {r.severity.value:6}  {r.description}\n")
    return 0


def main(argv: Optional[Sequence[str]] = None,
         stdout: Optional[TextIO] = None,
         stderr: Optional[TextIO] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    if args.version:
        out.write(f"pjhookcheck {__version__}\n")
        return 0
    if args.list_rules:
        return _list_rules(out)

    # validate --disable
    unknown = [d for d in args.disable if d not in REGISTRY_BY_ID]
    if unknown:
        err.write(f"pjhookcheck: unknown rule id(s): {', '.join(sorted(unknown))}\n")
        err.write(f"pjhookcheck: known: {', '.join(all_rule_ids())}\n")
        return 2

    if not args.paths:
        err.write("pjhookcheck: no paths given\n")
        return 2

    options = Options(
        disabled=frozenset(args.disable),
        strict=args.strict,
        include_info=args.include_info,
        max_files=max(0, int(args.max_files)),
        max_bytes=max(0, int(args.max_bytes)),
    )
    globs = tuple(args.glob) if args.glob else ()

    result = scan_paths(list(args.paths), globs, options)
    verdict = compute_verdict(result, options)

    if args.json:
        render_json(result, verdict, options, out, err)
    else:
        render_text(result, verdict, options, out, err)

    return exit_code(verdict)
