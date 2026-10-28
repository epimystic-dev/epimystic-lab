"""Command-line entry for mcptoolcheck.

Invokable as ``python -m mcptoolcheck`` (via __main__.py). argparse
owns ``--help`` and unknown-flag handling, which keeps the exit-code
contract documented in CONVENTIONS.md intact.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence, TextIO

from . import __version__
from .report import write_json, write_text
from .scanner import scan_paths
from .types import Options
from .verdict import exit_code


def _parse_argv(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="mcptoolcheck",
        description=(
            "Static linter for MCP tool-descriptor files (tools/list "
            "snapshots, server-side manifests, generic tool-advertise "
            "JSON). Flags twelve shape defects enabling approval-view "
            "fidelity gaps and silent descriptor drift."
        ),
    )
    # action="version" exits before argparse checks the required positional,
    # so `mcptoolcheck --version` works without a path - which the lab's
    # shared CLI contract requires (docs/CONVENTIONS.md).
    p.add_argument(
        "--version", action="version", version="mcptoolcheck " + __version__,
    )
    p.add_argument(
        "paths", nargs="+", help="JSON file(s) or directory(ies) to scan"
    )
    p.add_argument(
        "--json", action="store_true",
        help="emit machine-readable JSON instead of text",
    )
    p.add_argument(
        "--strict", action="store_true",
        help=(
            "surface INFO rules and treat INFO-only outcomes as "
            "needs-attention"
        ),
    )
    p.add_argument(
        "--include-info", action="store_true",
        help="surface INFO rules in output (without upgrading verdict)",
    )
    p.add_argument(
        "--disable", action="append", default=[],
        metavar="RULE_ID",
        help="disable a rule (repeatable)",
    )
    p.add_argument(
        "--only", action="append", default=[],
        metavar="RULE_ID",
        help="run only the given rule (repeatable)",
    )
    return p.parse_args(list(argv))


def main(
    argv: Optional[Sequence[str]] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    args = _parse_argv(argv if argv is not None else sys.argv[1:])
    options = Options(
        strict=args.strict,
        include_info=args.include_info,
        disabled=tuple(args.disable),
        only=tuple(args.only),
    )
    result = scan_paths(args.paths, options)
    rc = exit_code(result.verdict, options)
    if args.json:
        write_json(result, stdout)
    else:
        # docs/CONVENTIONS.md Stdout / stderr discipline: a silent rc=0
        # text-mode run must produce zero bytes on stdout so downstream
        # jq / test -s / | head CI wrappers piping the tool's stdout can
        # rely on empty stdout meaning "nothing to look at". mcptoolcheck
        # follows Convention B (severity-tiered), so rc=0 means verdict
        # healthy with no HIGH / MEDIUM finding (and no --strict
        # escalation); the one-line verdict / counts summary is diagnostic
        # prose in that case and routes to stderr. On non-zero rc the
        # finding block carries actionable rule-id output and stays on
        # stdout so consumers that scrape stdout for MTC-* codes are
        # unchanged. write_text() is unchanged and remains the public
        # formatter; the routing decision lives in the CLI so a caller
        # that imports it directly still gets a self-contained report.
        if rc == 0:
            write_text(result, stderr)
        else:
            write_text(result, stdout)
    return rc


__all__ = ["main"]
