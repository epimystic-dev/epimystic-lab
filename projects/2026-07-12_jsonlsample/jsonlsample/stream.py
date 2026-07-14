"""Streaming JSONL I/O and dotted-path resolution.

Blank lines are skipped silently (a common convenience when files are
concatenated with `cat`); everything else is either a JSON record or a
parse error yielded as a `ParseErrorRecord`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Optional


@dataclass(frozen=True)
class ParseErrorRecord:
    """Represents a line that could not be parsed as JSON."""

    line_number: int
    message: str
    raw: str


def iter_jsonl(source: Iterable[str]) -> Iterator[tuple[int, Any]]:
    """Yield (line_number, record | ParseErrorRecord) for each non-blank line.

    Blank / whitespace-only lines are skipped. Line numbers are 1-based in
    the raw input (they count skipped blanks so error messages align with
    the source file).
    """
    for line_number, raw in enumerate(source, start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            yield (line_number, json.loads(stripped))
        except json.JSONDecodeError as exc:
            yield (
                line_number,
                ParseErrorRecord(
                    line_number=line_number,
                    message=str(exc),
                    raw=stripped,
                ),
            )


def _split_path(path: str) -> list[str]:
    """Split a dotted path into segments.

    Empty string means "the record itself". Dots inside a segment can be
    escaped with a backslash: `metrics\\.p50` -> `metrics.p50` as a single
    segment.
    """
    if not path:
        return []
    parts: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(path)
    while i < n:
        ch = path[i]
        if ch == "\\" and i + 1 < n:
            buf.append(path[i + 1])
            i += 2
            continue
        if ch == ".":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


_MISSING = object()


def resolve_path(record: Any, path: str) -> Any:
    """Return the value at `path` inside `record`, or the sentinel `MISSING`.

    Segments navigate dict keys; list indices are supported when a segment
    is an integer literal. Missing segments return the module-private
    `_MISSING` sentinel; callers should compare with `is _MISSING`.
    """
    if not path:
        return record
    cur: Any = record
    for seg in _split_path(path):
        if isinstance(cur, dict):
            if seg not in cur:
                return _MISSING
            cur = cur[seg]
        elif isinstance(cur, list):
            try:
                idx = int(seg)
            except ValueError:
                return _MISSING
            if idx < 0 or idx >= len(cur):
                return _MISSING
            cur = cur[idx]
        else:
            return _MISSING
    return cur


def path_missing(value: Any) -> bool:
    """Return True if `value` was returned by `resolve_path` as missing."""
    return value is _MISSING


# Expose the missing sentinel for tests that need identity comparison.
MISSING = _MISSING
