"""jsonlsample CLI.

Usage:
    jsonlsample [options] <file | ->

Modes (mutually exclusive):
    -n / --count K      reservoir sample of size K
    --fraction F        Bernoulli fraction sample (each row kept with p=F)
    --stratify PATH     stratified reservoir; sample --per-group K rows per
                        distinct value of PATH

Options:
    --seed N            PRNG seed (default: 0)
    --per-group K       per-stratum reservoir size (default: 1)
    --skip-parse-errors treat malformed JSON lines as skipped (default:
                        report to stderr and exit 2 at end)

Exit codes:
    0  success
    1  no records emitted (empty input or full rejection)
    2  parse error surfaced (unless --skip-parse-errors given)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterator, Sequence, TextIO

from jsonlsample import __version__
from jsonlsample.sample import (
    bernoulli_sample,
    reservoir_sample,
    stratified_reservoir_sample,
)
from jsonlsample.stream import ParseErrorRecord, iter_jsonl, path_missing, resolve_path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="jsonlsample",
        description=(
            "Deterministic reservoir / Bernoulli / stratified sampling for "
            "JSONL streams. Streaming, zero dependencies."
        ),
    )
    p.add_argument(
        "input",
        help='input file path, or "-" for stdin',
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "-n", "--count",
        type=int,
        metavar="K",
        help="uniform reservoir sample of size K",
    )
    mode.add_argument(
        "--fraction",
        type=float,
        metavar="F",
        help="keep each row with probability F (F in [0.0, 1.0])",
    )
    mode.add_argument(
        "--stratify",
        metavar="PATH",
        help="stratified reservoir keyed on dotted PATH; use --per-group",
    )
    p.add_argument(
        "--per-group",
        type=int,
        default=1,
        metavar="K",
        help="per-stratum reservoir size (default: 1)",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=0,
        help="PRNG seed for reproducibility (default: 0)",
    )
    p.add_argument(
        "--skip-parse-errors",
        action="store_true",
        help="skip malformed JSON lines silently (default: report + exit 2)",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"jsonlsample {__version__}",
    )
    return p


def _open_input(path: str) -> TextIO:
    if path == "-":
        return sys.stdin
    return open(path, "r", encoding="utf-8")


def _partition(
    src: Iterator,
    stderr: TextIO,
    skip_errors: bool,
) -> tuple[Iterator, list[ParseErrorRecord]]:
    """Split (line_number, record | error) into (records-iter, errors-list).

    The errors list is populated eagerly as the iterator is consumed by
    the sampling algorithms; callers should read it *after* consumption.
    """
    errors: list[ParseErrorRecord] = []

    def _iter():
        for _, item in src:
            if isinstance(item, ParseErrorRecord):
                errors.append(item)
                if not skip_errors:
                    stderr.write(
                        f"jsonlsample: parse error at line {item.line_number}: "
                        f"{item.message}\n"
                    )
                continue
            yield item

    return _iter(), errors


def run(argv: Sequence[str], stdout: TextIO = None, stderr: TextIO = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr

    ns = _build_parser().parse_args(argv)

    try:
        stream = _open_input(ns.input)
    except OSError as exc:
        stderr.write(f"jsonlsample: {ns.input}: {exc}\n")
        return 2

    parsed = iter_jsonl(stream)
    records_iter, errors = _partition(parsed, stderr, ns.skip_parse_errors)

    emitted = 0
    try:
        if ns.count is not None:
            if ns.count < 0:
                stderr.write("jsonlsample: --count must be non-negative\n")
                return 2
            picked = reservoir_sample(records_iter, ns.count, seed=ns.seed)
            for rec in picked:
                stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                emitted += 1

        elif ns.fraction is not None:
            if not (0.0 <= ns.fraction <= 1.0):
                stderr.write("jsonlsample: --fraction must be in [0.0, 1.0]\n")
                return 2
            for rec in bernoulli_sample(records_iter, ns.fraction, seed=ns.seed):
                stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                emitted += 1

        else:  # ns.stratify
            if ns.per_group <= 0:
                stderr.write("jsonlsample: --per-group must be positive\n")
                return 2
            path = ns.stratify

            def key_fn(record):
                val = resolve_path(record, path)
                if path_missing(val):
                    return ("__missing__", path)
                # Non-hashable values (dicts / lists) fall back to a JSON
                # canonical form so grouping remains deterministic.
                try:
                    hash(val)
                except TypeError:
                    return ("__json__", json.dumps(val, sort_keys=True))
                return val

            picked = stratified_reservoir_sample(
                records_iter, ns.per_group, key_fn, seed=ns.seed
            )
            for _, rec in picked:
                stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                emitted += 1

    finally:
        if stream is not sys.stdin:
            stream.close()

    if errors and not ns.skip_parse_errors:
        return 2
    if emitted == 0:
        return 1
    return 0


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
