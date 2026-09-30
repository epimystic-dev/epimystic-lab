"""Command-line entry point."""

import argparse
import os
import sys
from datetime import date
from typing import List, Optional

from . import __version__
from .config import (
    Config,
    DEFAULT_DUPLICATE_THRESHOLD,
    DEFAULT_HARD_BYTES,
    DEFAULT_HARD_INSTRUCTIONS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MIN_SECTION_TOKENS,
    DEFAULT_SOFT_BYTES,
    DEFAULT_SOFT_INSTRUCTIONS,
    DEFAULT_STALE_DAYS,
    DEFAULT_WALL_LENGTH,
    DEFAULT_FILES,
)
from .report import format_json, format_text
from .scanner import scan_path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentmdlint",
        description=(
            "Offline maintainability linter for agent instruction files. "
            "Scans AGENTS.md-family files and emits a structured verdict."
        ),
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository root or a specific file (default: current directory).",
    )
    p.add_argument("--version", action="store_true", help="print version and exit.")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text.")
    p.add_argument(
        "--strict",
        action="store_true",
        help="escalate info-only and no-file-found outcomes to a nonzero exit.",
    )
    p.add_argument(
        "--include-info",
        action="store_true",
        help="include INFO-severity findings in text output (JSON always includes them).",
    )
    p.add_argument("--soft-bytes", type=int, default=DEFAULT_SOFT_BYTES)
    p.add_argument("--hard-bytes", type=int, default=DEFAULT_HARD_BYTES)
    p.add_argument("--soft-instructions", type=int, default=DEFAULT_SOFT_INSTRUCTIONS)
    p.add_argument("--hard-instructions", type=int, default=DEFAULT_HARD_INSTRUCTIONS)
    p.add_argument(
        "--duplicate-threshold", type=float, default=DEFAULT_DUPLICATE_THRESHOLD,
        help="Jaccard-token-set similarity threshold for AGENTMD-003 (0.0-1.0).",
    )
    p.add_argument(
        "--min-section-tokens", type=int, default=DEFAULT_MIN_SECTION_TOKENS,
        help="minimum tokens a section must have before AGENTMD-005 stops firing.",
    )
    p.add_argument("--stale-days", type=int, default=DEFAULT_STALE_DAYS)
    p.add_argument(
        "--today",
        default=None,
        help="reference date for AGENTMD-007 in YYYY-MM-DD form (default: system date).",
    )
    p.add_argument("--wall-length", type=int, default=DEFAULT_WALL_LENGTH)
    p.add_argument(
        "--files",
        default=None,
        help=(
            "comma-separated list of filenames to scan (overrides defaults). "
            "Example: AGENTS.md,MY_INSTRUCTIONS.md"
        ),
    )
    p.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    return p


def _make_config(args: argparse.Namespace) -> Config:
    files = DEFAULT_FILES
    if args.files:
        files = tuple(f.strip() for f in args.files.split(",") if f.strip())
    today = None
    if args.today:
        try:
            today = date.fromisoformat(args.today)
        except ValueError:
            raise SystemExit("invalid --today value (expected YYYY-MM-DD): " + args.today)
    return Config(
        files=files,
        soft_bytes=args.soft_bytes,
        hard_bytes=args.hard_bytes,
        soft_instructions=args.soft_instructions,
        hard_instructions=args.hard_instructions,
        duplicate_threshold=args.duplicate_threshold,
        min_section_tokens=args.min_section_tokens,
        stale_days=args.stale_days,
        wall_length=args.wall_length,
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        today=today,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        sys.stdout.write("agentmdlint " + __version__ + "\n")
        return 0

    path = args.path
    if not os.path.exists(path):
        sys.stderr.write("agentmdlint: path does not exist: " + path + "\n")
        return 2

    try:
        cfg = _make_config(args)
    except SystemExit as e:
        sys.stderr.write("agentmdlint: " + str(e) + "\n")
        return 2

    report = scan_path(path, cfg)

    from .verdict import compute_verdict
    _, exit_code = compute_verdict(report, cfg, strict=args.strict)

    if args.json:
        sys.stdout.write(format_json(report, cfg, strict=args.strict, include_info=True) + "\n")
        return exit_code

    # docs/CONVENTIONS.md Stdout / stderr discipline: a silent rc=0
    # text-mode run must produce zero bytes on stdout so downstream
    # jq / test -s / | head CI wrappers piping the tool's stdout can
    # rely on empty stdout meaning "nothing to look at". agentmdlint
    # follows Convention B (severity-tiered), so rc=0 means no
    # medium/high/critical findings and no unknown verdict; the
    # verdict-and-counts block is diagnostic prose in that case and
    # routes to stderr. On non-zero rc the same block frames actionable
    # findings and stays on stdout so consumers that already scrape
    # stdout for AGENTMD-* rule codes are unchanged. format_text() is
    # unchanged and remains the public formatter API; the routing
    # decision lives in the CLI so a caller that imports it directly
    # still gets a self-contained report string.
    text_output = format_text(report, cfg, strict=args.strict, include_info=args.include_info)
    if exit_code == 0:
        sys.stderr.write(text_output)
    else:
        sys.stdout.write(text_output)
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
