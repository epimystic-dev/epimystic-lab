"""CLI entry point: ``python -m jsonlcheck``."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .core import Options, Severity, check_path, check_stream


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jsonlcheck",
        description=(
            "Strict streaming JSONL validator. Reports parse errors and "
            "structural problems with line:column diagnostics. Pure stdlib."
        ),
    )
    p.add_argument("paths", nargs="*", help="JSONL file paths; '-' for stdin (default).")
    p.add_argument("--version", action="version", version=f"jsonlcheck {__version__}")
    p.add_argument("--no-bom", action="store_true", help="do not flag UTF-8 BOMs")
    p.add_argument("--allow-blank", action="store_true", help="do not flag blank lines")
    p.add_argument("--allow-nan", action="store_true", help="do not flag NaN/Infinity literals")
    p.add_argument("--allow-duplicate-keys", action="store_true", help="do not flag duplicate object keys")
    p.add_argument("--allow-control-chars", action="store_true", help="do not flag unescaped control characters in strings")
    p.add_argument("--homogeneous", action="store_true", help="require all non-blank lines to share the same top-level JSON type")
    p.add_argument("--require-key", action="append", default=[], metavar="KEY", help="require a key at the top-level object (repeatable)")
    p.add_argument("--no-final-newline-check", action="store_true", help="do not warn on missing trailing newline")
    p.add_argument("--max-issues", type=int, default=None, metavar="N", help="stop after N issues (per file)")
    p.add_argument("--quiet", action="store_true", help="suppress per-issue output; only set exit code")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    opts = Options(
        bom=not args.no_bom,
        blank_lines=not args.allow_blank,
        nan_inf=not args.allow_nan,
        duplicate_keys=not args.allow_duplicate_keys,
        control_chars=not args.allow_control_chars,
        homogeneous=args.homogeneous,
        required_keys=tuple(args.require_key),
        final_newline=not args.no_final_newline_check,
        max_issues=args.max_issues,
    )

    paths = args.paths or ["-"]
    any_error = False
    for path in paths:
        if path == "-":
            issues = check_stream(sys.stdin, options=opts)
            label = "<stdin>"
        else:
            issues = check_path(path, options=opts)
            label = path
        for issue in issues:
            if not args.quiet:
                sys.stderr.write(issue.format(label) + "\n")
            if issue.severity == Severity.ERROR:
                any_error = True
    return 1 if any_error else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
