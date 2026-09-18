"""Command-line interface for sarifcheck."""

from __future__ import annotations

import argparse
import os
import sys
from typing import FrozenSet, List, Optional, Sequence

from . import __version__
from . import limits as limits_mod
from .report import (
    DISCLAIMER,
    format_findings_text,
    format_json,
    format_summary_text,
)
from .rules import ALL_RULES
from .scanner import (
    DEFAULT_GLOBS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    build_options,
    scan_path,
)
from .types import Profile
from .verdict import compute_verdict, exit_code_for


PROG = "sarifcheck"

ALL_PROFILES = (Profile.SPEC.value, Profile.INGEST.value, Profile.HYGIENE.value)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Offline linter for SARIF 2.1.0 result files. " + DISCLAIMER
            + " It flags absolute host paths, missing required fields, and "
            "runs that exceed documented ingest caps. Intended slot: between "
            "the scanner step and the upload step in CI."
        ),
        epilog=(
            "Rules carry a profile: spec (a MUST in OASIS SARIF 2.1.0), "
            "ingest (one documented code-scanning endpoint's requirement or "
            "numeric ceiling, NOT part of the standard), and hygiene (legal "
            "SARIF that has tripped consumers or that carries host layout). "
            "Use --profile to select. Use --show-limits to print every "
            "numeric ceiling with its source URL and the date it was read."
        ),
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help="SARIF file, or a directory to scan for *.sarif / *.sarif.json "
             "(default: current directory).",
    )
    parser.add_argument("--version", action="version", version=PROG + " " + __version__)
    parser.add_argument("--json", action="store_true",
                        help="Emit deterministic JSON on stdout.")
    parser.add_argument("--strict", action="store_true",
                        help="Escalate INFO to needs-attention; no files scanned exits 2.")
    parser.add_argument("--include-info", action="store_true",
                        help="Show INFO findings (hidden by default; always counted).")
    parser.add_argument("--disable", action="append", default=[], metavar="CODE",
                        help="Disable one rule by code (repeatable). Example: --disable SRF-018")
    parser.add_argument("--profile", default="all",
                        choices=("spec", "ingest", "hygiene", "all"),
                        help="Which rule profile to run (default: all).")
    parser.add_argument("--ignore-rule-id", action="append", default=[], metavar="RULE_ID",
                        help="Suppress path-shape findings for results carrying this "
                             "SARIF ruleId (repeatable). For scanners whose job is to "
                             "report paths.")
    parser.add_argument("--allow-path-in-message", action="store_true",
                        help="Turn off SRF-006 entirely (host-layout shapes in "
                             "result message text).")
    parser.add_argument("--show-matches", action="store_true",
                        help="Print the matched text for path-shape and token-shape "
                             "findings. Off by default so the linter does not "
                             "republish a host path into a CI log. Local use only.")
    parser.add_argument("--show-limits", action="store_true",
                        help="Print every ingest limit with its source URL and "
                             "retrieval date, then exit 0.")
    parser.add_argument("--limit", action="append", default=[], metavar="NAME=VALUE",
                        help="Override one documented ingest limit (repeatable).")
    parser.add_argument("--limits-file", default=None, metavar="PATH",
                        help="JSON object of {limit_name: integer} overriding the "
                             "built-in table.")
    parser.add_argument("--glob", action="append", default=[], metavar="PATTERN",
                        help="Extend the default directory-scan globs (repeatable).")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                        help="Cap files scanned per run (default "
                             + str(DEFAULT_MAX_FILES) + ").")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help="Refuse to parse a file larger than this many bytes "
                             "(default " + str(DEFAULT_MAX_BYTES) + ").")
    parser.add_argument("--list-rules", action="store_true",
                        help="Print the rule registry and exit 0.")
    return parser


def _print_rules(stream) -> None:
    for rule in ALL_RULES:
        stream.write(
            rule.id + " " + rule.severity.value + " [" + rule.profile.value + "] "
            + rule.title + "\n"
        )


def _profiles_for(name: str) -> FrozenSet[str]:
    if name == "all":
        return frozenset(ALL_PROFILES)
    return frozenset((name,))


def _unknown_codes(codes: Sequence[str]) -> List[str]:
    known = set(rule.id for rule in ALL_RULES)
    return [code for code in codes if code not in known]


def main(argv: Optional[Sequence[str]] = None, stdout=None, stderr=None) -> int:
    if stdout is None:
        stdout = sys.stdout
    if stderr is None:
        stderr = sys.stderr
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list_rules:
        _print_rules(stdout)
        return 0

    if args.show_limits:
        stdout.write(limits_mod.render_table())
        return 0

    limits = limits_mod.default_limits()
    if args.limits_file is not None:
        try:
            limits.update(limits_mod.load_limits_file(args.limits_file))
        except limits_mod.LimitError as exc:
            stderr.write(PROG + ": " + str(exc) + "\n")
            return 2
    for spec in args.limit:
        try:
            name, value = limits_mod.parse_override(spec)
        except limits_mod.LimitError as exc:
            stderr.write(PROG + ": " + str(exc) + "\n")
            return 2
        limits[name] = value

    unknown = _unknown_codes(args.disable)
    if unknown:
        stderr.write(
            PROG + ": unknown rule code(s) passed to --disable: "
            + ", ".join(unknown) + "; see --list-rules\n"
        )
        return 2

    if args.max_files <= 0:
        stderr.write(PROG + ": --max-files must be > 0\n")
        return 2
    if args.max_bytes <= 0:
        stderr.write(PROG + ": --max-bytes must be > 0\n")
        return 2

    if not os.path.exists(args.path):
        stderr.write(PROG + ": path does not exist: " + args.path + "\n")
        return 2

    if args.show_matches:
        stderr.write(
            PROG + ": --show-matches is on; matched host paths and token-shaped "
            "strings will be printed to stdout. Do not use this in a public CI log.\n"
        )

    profiles = _profiles_for(args.profile)
    options = build_options(
        limits=limits,
        profiles=profiles,
        disabled=frozenset(args.disable),
        ignore_rule_ids=frozenset(args.ignore_rule_id),
        allow_path_in_message=args.allow_path_in_message,
        show_matches=args.show_matches,
    )

    result = scan_path(
        args.path,
        options,
        globs=tuple(DEFAULT_GLOBS) + tuple(args.glob),
        max_files=args.max_files,
        max_bytes=args.max_bytes,
    )

    if args.json:
        stdout.write(format_json(
            result,
            tool=PROG,
            version=__version__,
            strict=args.strict,
            include_info=args.include_info,
            show_matches=args.show_matches,
            profiles=sorted(profiles),
            limits=limits,
        ))
    else:
        stdout.write(format_findings_text(
            result,
            include_info=args.include_info,
            show_matches=args.show_matches,
        ))
    stderr.write(format_summary_text(
        result,
        strict=args.strict,
        include_info=args.include_info,
        profiles=sorted(profiles),
    ))

    verdict = compute_verdict(result, strict=args.strict)
    return exit_code_for(verdict, strict=args.strict, hard_error=bool(result.errors))
