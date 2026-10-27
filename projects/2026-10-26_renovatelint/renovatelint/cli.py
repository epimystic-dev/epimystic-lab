"""Command-line entry for renovatelint.

Invokable as ``python -m renovatelint`` (via __main__.py). argparse
owns ``--help`` and unknown-flag handling, keeping the exit-code
contract documented in CONVENTIONS.md intact.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional, Sequence, TextIO

from . import __version__
from .report import write_json, write_text
from .scanner import scan_paths
from .types import DEFAULT_MIN_QUARANTINE_DAYS, Options
from .verdict import exit_code


def _parse_argv(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="renovatelint",
        description=(
            "Static linter for Renovate bot config files. Flags "
            "twelve shape defects enabling supply-chain, "
            "unguarded-automerge, and credential-leak attacks "
            "against Renovate-managed dependency updates."
        ),
    )
    p.add_argument(
        "--version", action="version",
        version="renovatelint " + __version__,
    )
    p.add_argument(
        "paths", nargs="+",
        help=(
            "renovate.json / .renovaterc / package.json file(s) or "
            "directory(ies) to scan"
        ),
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
    p.add_argument(
        "--min-quarantine-days", type=int,
        default=DEFAULT_MIN_QUARANTINE_DAYS,
        metavar="N",
        help=(
            "RNV-010 quarantine floor in days (default: "
            + str(DEFAULT_MIN_QUARANTINE_DAYS) + ")"
        ),
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
        min_quarantine_days=args.min_quarantine_days,
    )
    result = scan_paths(args.paths, options)
    rc = exit_code(result.verdict, options)
    if args.json:
        write_json(result, stdout)
    else:
        if rc == 0:
            write_text(result, stderr)
        else:
            write_text(result, stdout)
    return rc


__all__ = ["main"]
