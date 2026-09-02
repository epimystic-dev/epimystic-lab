from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import Config, DEFAULT_GLOBS, DEFAULT_MAX_FILES, DEFAULT_MAX_BYTES
from .report import render_json, render_text
from .rules import ALL_RULES
from .scanner import scan_path
from .verdict import compute_verdict, exit_code


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="elevatescan",
        description=(
            "Offline static scanner for instruction-privilege-escalation shapes in "
            "files an agent will consume as low-privilege observations, tool outputs, "
            "or user-provided context."
        ),
    )
    p.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: cwd)")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p.add_argument("--strict", action="store_true", help="INFO -> needs-attention; no-files -> exit 2.")
    p.add_argument(
        "--include-info", action="store_true",
        help="Surface INFO findings in text output (they are always counted).",
    )
    p.add_argument(
        "--disable", action="append", default=[], metavar="RULE_ID",
        help="Disable a rule id (repeatable).",
    )
    p.add_argument(
        "--glob", action="append", default=[], metavar="PATTERN",
        help="Additional file glob (repeatable). Default: " + ",".join(DEFAULT_GLOBS),
    )
    p.add_argument(
        "--max-files", type=int, default=DEFAULT_MAX_FILES,
        help=f"Cap on number of files scanned (default: {DEFAULT_MAX_FILES}).",
    )
    p.add_argument(
        "--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
        help=f"Cap on bytes read per file (default: {DEFAULT_MAX_BYTES}).",
    )
    p.add_argument(
        "--list-rules", action="store_true",
        help="Print the rule registry and exit 0.",
    )
    p.add_argument("--version", action="version", version=f"elevatescan {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    ns = parser.parse_args(argv)

    if ns.list_rules:
        for r in ALL_RULES:
            print(f"{r.id} {r.severity.value} {r.description}")
        return 0

    if ns.max_files <= 0:
        print("elevatescan: --max-files must be a positive integer", file=sys.stderr)
        return 2
    if ns.max_bytes <= 0:
        print("elevatescan: --max-bytes must be a positive integer", file=sys.stderr)
        return 2

    path = Path(ns.path)
    if not path.exists():
        print(f"elevatescan: path does not exist: {path}", file=sys.stderr)
        return 2

    globs = list(DEFAULT_GLOBS) + list(ns.glob) if ns.glob else list(DEFAULT_GLOBS)
    config = Config(
        globs=globs,
        disabled_rules=set(ns.disable),
        max_files=ns.max_files,
        max_bytes=ns.max_bytes,
        strict=ns.strict,
        include_info=ns.include_info,
    )
    result = scan_path(path, config)
    verdict = compute_verdict(result, config)
    if ns.json:
        sys.stdout.write(render_json(result, verdict, config))
    else:
        sys.stdout.write(render_text(result, verdict, config))
    return exit_code(verdict, config)
