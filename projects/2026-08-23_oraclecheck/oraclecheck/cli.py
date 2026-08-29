"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from oraclecheck import __version__
from oraclecheck.config import Config
from oraclecheck.report import build_report, render_json, render_text
from oraclecheck.scanner import scan_path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oraclecheck",
        description=(
            "Offline AST linter for Python test files: detects state-anchored "
            "oracles (assertions whose expected value derives from the code "
            "under test)."
        ),
    )
    p.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: current directory)")
    p.add_argument("--version", action="store_true", help="Print version and exit")
    p.add_argument("--json", action="store_true", help="Emit JSON report to stdout instead of text")
    p.add_argument("--strict", action="store_true", help="Escalate INFO findings and no-files-scanned to exit 1 / 2")
    p.add_argument("--include-info", action="store_true", help="Show INFO-severity findings (hidden by default)")
    p.add_argument("--sut", metavar="MODULE", default=None, help="Name of the module under test (overrides per-file heuristic)")
    p.add_argument("--max-files", type=int, default=None, help="Cap on discovered files (default 1000)")
    p.add_argument("--max-bytes", type=int, default=None, help="Cap on per-file bytes read (default 1 MiB)")
    p.add_argument("--disable", metavar="RULE_ID", action="append", default=[], help="Disable a rule (repeatable)")
    p.add_argument("--test-glob", metavar="PATTERN", action="append", default=[], help="Additional test-file glob (repeatable)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"oraclecheck {__version__}")
        return 0

    from oraclecheck.config import DEFAULT_TEST_GLOBS
    globs = tuple(DEFAULT_TEST_GLOBS) + tuple(args.test_glob or ())

    config = Config(
        sut_module=args.sut,
        include_info=args.include_info,
        strict=args.strict,
        disabled_rules=frozenset(args.disable or ()),
        test_globs=globs,
    )
    if args.max_files is not None:
        if args.max_files <= 0:
            print("--max-files must be positive", file=sys.stderr)
            return 2
        config.max_files = args.max_files
    if args.max_bytes is not None:
        if args.max_bytes <= 0:
            print("--max-bytes must be positive", file=sys.stderr)
            return 2
        config.max_bytes = args.max_bytes

    import os
    if not os.path.exists(args.path):
        print(f"path does not exist: {args.path}", file=sys.stderr)
        return 2

    results = scan_path(args.path, config)
    report = build_report(results, strict=args.strict, include_info=args.include_info)

    if args.json:
        sys.stdout.write(render_json(report) + "\n")
    else:
        sys.stdout.write(render_text(report))

    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
