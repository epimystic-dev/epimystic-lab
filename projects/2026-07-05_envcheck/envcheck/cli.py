"""Command-line interface for ``envcheck``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .core import CheckOptions, Diagnostic, check, parse


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="envcheck",
        description=(
            "Drift and secret checks for dotenv files. Compares a template "
            "(e.g. .env.example) against an actual .env, flags key drift, "
            "syntax issues, and probable credentials pasted into either."
        ),
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"envcheck {__version__}",
    )
    p.add_argument(
        "template",
        nargs="?",
        default=".env.example",
        help="Template path (default: .env.example).",
    )
    p.add_argument(
        "env",
        nargs="?",
        default=None,
        help="Actual env path (default: .env if it exists, else drift skipped).",
    )
    p.add_argument(
        "--no-drift",
        action="store_true",
        help="Skip the template<->env drift comparison.",
    )
    p.add_argument(
        "--no-secrets",
        action="store_true",
        help="Skip the credential-pattern check.",
    )
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--max-issues",
        type=int,
        default=None,
        help="Stop after N issues (default: report all).",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the final summary line.",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    template_path = Path(args.template)
    if not template_path.exists():
        print(f"envcheck: template not found: {template_path}", file=sys.stderr)
        return 2

    env_path: Optional[Path]
    if args.env is not None:
        env_path = Path(args.env)
        if not env_path.exists():
            print(f"envcheck: env not found: {env_path}", file=sys.stderr)
            return 2
    else:
        default_env = Path(".env")
        env_path = default_env if default_env.exists() else None

    try:
        template = parse(template_path)
    except OSError as exc:
        print(f"envcheck: cannot read template {template_path}: {exc}", file=sys.stderr)
        return 2

    env_parse = None
    if env_path is not None:
        try:
            env_parse = parse(env_path)
        except OSError as exc:
            print(f"envcheck: cannot read env {env_path}: {exc}", file=sys.stderr)
            return 2

    opts = CheckOptions(
        drift=not args.no_drift,
        secrets=not args.no_secrets,
        max_issues=args.max_issues,
    )
    diags = check(template, env_parse, opts)

    if args.format == "json":
        _emit_json(diags, str(template_path), str(env_path) if env_path else None)
    else:
        _emit_text(diags, str(template_path), str(env_path) if env_path else None)

    if not args.quiet and args.format == "text":
        _summary(diags)

    return 0 if not diags else 1


def _file_for(d: Diagnostic, tpath: str, epath: Optional[str]) -> str:
    if d.source == "env" and epath is not None:
        return epath
    return tpath


def _emit_json(diags: List[Diagnostic], tpath: str, epath: Optional[str]) -> None:
    for d in diags:
        record = {
            "code": d.code,
            "line": d.line,
            "column": d.column,
            "message": d.message,
            "file": _file_for(d, tpath, epath),
        }
        if d.key is not None:
            record["key"] = d.key
        print(json.dumps(record, ensure_ascii=False))


def _emit_text(diags: List[Diagnostic], tpath: str, epath: Optional[str]) -> None:
    for d in diags:
        print(d.format(_file_for(d, tpath, epath)))


def _summary(diags: List[Diagnostic]) -> None:
    by_code: dict[str, int] = {}
    for d in diags:
        by_code[d.code] = by_code.get(d.code, 0) + 1
    total = len(diags)
    if total == 0:
        print("envcheck: no issues", file=sys.stderr)
        return
    parts = ", ".join(f"{k}: {v}" for k, v in sorted(by_code.items()))
    print(f"envcheck: {total} issue(s) ({parts})", file=sys.stderr)
