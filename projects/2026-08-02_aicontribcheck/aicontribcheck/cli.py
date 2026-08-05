"""Command-line entry point for aicontribcheck."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

from . import __version__, patterns
from .rules import run_rules, rollup
from .report import format_json, format_text, exit_code
from .scanner import discover_policy_files, read_policy_file
from .types import FileScan, RepoReport


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aicontribcheck",
        description=(
            "Offline AI-contribution-policy detector for open-source "
            "repositories."
        ),
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Repository root (or a single policy file). Defaults to '.'.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human text.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Treat 'unknown' verdict as failure (exit 2).",
    )
    p.add_argument(
        "--include-info",
        action="store_true",
        help="Include INFO-severity findings in text output.",
    )
    p.add_argument(
        "--extra-tool-name",
        action="append",
        default=[],
        metavar="NAME",
        dest="extra_tool_names",
        help=(
            "Also recognise NAME as an assistant/product name (repeatable). "
            "The shipped patterns are vendor-neutral and match generic markers "
            "('ai', 'llm', 'ai-generated', 'coding agent', ...); use this to add "
            "the specific product names your policies mention."
        ),
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"aicontribcheck {__version__}",
    )
    return p


def scan_repo(root: str) -> RepoReport:
    report = RepoReport(root=os.path.abspath(root))
    for kind, path in discover_policy_files(root):
        fs = FileScan(path=path, kind=kind)
        text, err = read_policy_file(path)
        if err is not None:
            fs.read_error = err
        else:
            assert text is not None
            run_rules(fs, text)
        report.files_scanned.append(fs)
    rollup(report)
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    target = args.path
    if not os.path.exists(target):
        print(f"aicontribcheck: no such path: {target}", file=sys.stderr)
        return 2

    # Names supplied here extend both the AI marker used by the ban/allow/disclosure
    # rules and the named-tool evidence rule; the shipped defaults name no vendor.
    if args.extra_tool_names:
        patterns.register_tool_names(args.extra_tool_names)

    report = scan_repo(target)

    if args.json:
        print(format_json(report))
    else:
        text_output = format_text(report)
        if not args.include_info:
            # Filter INFO lines from human output for less noise.
            filtered: List[str] = []
            skip_next_evidence = False
            for line in text_output.splitlines():
                if skip_next_evidence:
                    skip_next_evidence = False
                    if line.startswith("          evidence:"):
                        continue
                if "[INFO ]" in line:
                    skip_next_evidence = True
                    continue
                filtered.append(line)
            text_output = "\n".join(filtered)
        print(text_output)
    return exit_code(report, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
