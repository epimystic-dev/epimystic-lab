"""Command-line entry point for licensechain."""

from __future__ import annotations
import argparse
import sys
from typing import List, Optional

from . import __version__
from .loader import load_manifest, LoadError
from .rules import check_chain, Severity
from .report import format_text, format_json, compute_exit_code


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="licensechain",
        description=(
            "Offline license-chain hygiene linter for AI supply chains "
            "(dataset -> model -> application). Reads a JSON manifest and "
            "reports missing licenses, incompatible combinations, dropped "
            "copyleft obligations, and share-alike violations."
        ),
    )
    p.add_argument(
        "manifest",
        nargs="?",
        default="-",
        help="path to a manifest JSON file (or '-' to read from stdin)",
    )
    p.add_argument(
        "--json", action="store_true",
        help="emit findings as JSON instead of human-readable text",
    )
    p.add_argument(
        "--strict", action="store_true",
        help="promote warnings to errors for exit-code purposes",
    )
    p.add_argument(
        "--include-info", action="store_true",
        help="include severity=INFO findings (e.g. orphan components)",
    )
    p.add_argument(
        "--version", action="version",
        version=f"licensechain {__version__}",
    )
    return p


def _read_source(path: str) -> tuple[str, str]:
    """Return (text, label). label is used in the report header."""
    if path == "-":
        return sys.stdin.read(), "<stdin>"
    return path, path


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    source, label = _read_source(args.manifest)
    try:
        chain = load_manifest(source)
    except LoadError as e:
        # Structural manifest failures go to stderr and exit 2 (matches
        # convention: 2 = something the user must fix before results
        # are trustworthy).
        print(f"licensechain: manifest load error: {e}", file=sys.stderr)
        return 2

    findings = check_chain(chain)

    if not args.include_info:
        findings = [f for f in findings if f.severity != Severity.INFO]

    if args.json:
        sys.stdout.write(format_json(findings, source_label=label))
    else:
        sys.stdout.write(format_text(findings, source_label=label))

    return compute_exit_code(findings, strict=args.strict)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
