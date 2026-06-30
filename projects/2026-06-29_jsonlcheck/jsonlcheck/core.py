"""Streaming JSONL validation core.

Reads a line-delimited JSON stream one line at a time, yielding structured
Issue records. The reader never accumulates lines in memory beyond the line
currently being parsed.

Checks performed (all on by default; each can be disabled via Options):

    parse           per-line JSON parse (line:column on failure)
    bom             reject byte-order marks at the start of file or a line
    blank_lines     reject blank or whitespace-only lines
    nan_inf         reject NaN / Infinity / -Infinity numeric literals
                    (RFC 8259 forbids them; stdlib accepts them by default)
    duplicate_keys  reject duplicate keys in any object on a line
    control_chars   reject U+0000..U+001F inside JSON string values
                    (RFC 8259 forbids unescaped control chars; some
                    producers emit them literally)
    homogeneous     all non-empty lines must share the same JSON top-level
                    type (object/array/string/number/bool/null)
    required_keys   if the top-level is an object, require these keys
    final_newline   the file must end with a single trailing newline

The reader does not enforce a schema beyond these structural rules; pair
with a JSON Schema validator if field-level checks are needed.
"""

from __future__ import annotations

import gzip
import io
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import IO, Iterable, Iterator, List, Optional, Sequence, Union

PathLike = Union[str, "os.PathLike[str]"]

_UTF8_BOM = "﻿"
_TOP_LEVEL_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "bool": bool,
    "null": type(None),
}


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Issue:
    """A single validation finding for one line of a JSONL stream."""

    line: int           # 1-based line number
    column: Optional[int]  # 1-based column, or None if not applicable
    code: str           # short stable identifier, e.g. "parse-error"
    message: str        # human-readable detail
    severity: Severity = Severity.ERROR

    def format(self, path: str = "<stdin>") -> str:
        col = f":{self.column}" if self.column is not None else ""
        return f"{path}:{self.line}{col}: {self.severity.value}: [{self.code}] {self.message}"


@dataclass
class Options:
    """Per-run validation options. All checks default to enabled."""

    bom: bool = True
    blank_lines: bool = True
    nan_inf: bool = True
    duplicate_keys: bool = True
    control_chars: bool = True
    homogeneous: bool = False  # opt-in: not all files are homogeneous
    required_keys: Sequence[str] = field(default_factory=tuple)
    final_newline: bool = True
    max_issues: Optional[int] = None  # stop yielding after N (None = no cap)


# ---------- duplicate-key-rejecting JSON decoder ----------

def _no_dup_object_pairs(pairs: List[tuple]) -> dict:
    """object_pairs_hook for json.loads that rejects duplicate keys."""
    seen: dict = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"duplicate object key: {k!r}")
        seen[k] = v
    return seen


# ---------- control-char detector ----------

# RFC 8259 §7: unescaped characters U+0000..U+001F are forbidden inside a
# JSON string. The json module accepts them when strict=False (its default
# is True, but the error message is generic). We pre-scan the raw bytes for
# control chars inside string contexts and surface a clearer error.
def _find_unescaped_control(raw: str) -> Optional[int]:
    """Return the 0-based offset of a forbidden control char inside a string,
    or None if none found. Scans top to bottom respecting backslash escapes
    and the in-string flag. Returns the first offset found."""
    in_str = False
    escape = False
    for i, ch in enumerate(raw):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            o = ord(ch)
            if o < 0x20:
                return i
    return None


# ---------- line iterator ----------

def _open_text(path: PathLike) -> IO[str]:
    """Open a path for line-by-line text reading, auto-detecting gzip."""
    p = os.fspath(path)
    if p.endswith(".gz"):
        return gzip.open(p, "rt", encoding="utf-8", newline="")
    return open(p, "rt", encoding="utf-8", newline="")


def iter_lines(stream: IO[str]) -> Iterator[tuple]:
    """Yield (lineno, raw_line_without_terminator, ended_with_newline) tuples.
    The reader treats only LF and CRLF as line terminators. A final line with
    no terminator is yielded with ended_with_newline=False."""
    lineno = 0
    while True:
        raw = stream.readline()
        if not raw:
            return
        lineno += 1
        ended = raw.endswith("\n")
        # strip exactly one trailing newline (LF or CRLF) but no other ws
        if raw.endswith("\r\n"):
            body = raw[:-2]
        elif ended:
            body = raw[:-1]
        else:
            body = raw
        yield lineno, body, ended


# ---------- main check loop ----------

def check_stream(stream: IO[str], *, options: Optional[Options] = None) -> Iterator[Issue]:
    """Yield Issue records for a single JSONL text stream.

    The caller is responsible for opening the stream in text mode with the
    correct encoding (utf-8 is required for JSONL per RFC 7464)."""
    opts = options or Options()
    issued = 0
    seen_top_level: Optional[str] = None
    last_ended_with_newline = True
    saw_any_line = False

    def emit(issue: Issue) -> Iterator[Issue]:
        nonlocal issued
        issued += 1
        yield issue

    for lineno, body, ended in iter_lines(stream):
        saw_any_line = True
        last_ended_with_newline = ended

        # BOM: always strip (so subsequent parse can succeed); only flag it
        # if the check is enabled. Stripping silently when bom=False matches
        # the user's stated intent: don't tell me about BOMs, just handle them.
        if body.startswith(_UTF8_BOM):
            if opts.bom:
                yield from emit(Issue(
                    line=lineno,
                    column=1,
                    code="bom",
                    message="line begins with a UTF-8 byte-order mark (U+FEFF); strip it",
                ))
                if opts.max_issues and issued >= opts.max_issues:
                    return
            body = body.lstrip(_UTF8_BOM)

        # blank line
        if not body or body.strip() == "":
            if opts.blank_lines:
                yield from emit(Issue(
                    line=lineno,
                    column=None,
                    code="blank-line",
                    message="line is blank or whitespace-only",
                ))
                if opts.max_issues and issued >= opts.max_issues:
                    return
            continue

        # control chars inside strings (pre-scan)
        if opts.control_chars:
            off = _find_unescaped_control(body)
            if off is not None:
                yield from emit(Issue(
                    line=lineno,
                    column=off + 1,
                    code="control-char",
                    message=(
                        f"unescaped control character U+{ord(body[off]):04X} "
                        f"in JSON string"
                    ),
                ))
                if opts.max_issues and issued >= opts.max_issues:
                    return
                # continue with parse anyway to surface other issues

        # primary parse with chosen options
        parse_kwargs: dict = {}
        if opts.duplicate_keys:
            parse_kwargs["object_pairs_hook"] = _no_dup_object_pairs
        # If the user opted out of control-char checking, tell the stdlib
        # parser to also tolerate literal control chars inside strings.
        if not opts.control_chars:
            parse_kwargs["strict"] = False
        try:
            value = json.loads(body, **parse_kwargs)
        except json.JSONDecodeError as e:
            yield from emit(Issue(
                line=lineno,
                column=e.colno,
                code="parse-error",
                message=f"{e.msg}",
            ))
            if opts.max_issues and issued >= opts.max_issues:
                return
            continue
        except ValueError as e:
            # duplicate-key hook raises ValueError
            yield from emit(Issue(
                line=lineno,
                column=None,
                code="duplicate-key",
                message=str(e),
            ))
            if opts.max_issues and issued >= opts.max_issues:
                return
            continue

        # NaN / Infinity check (the stdlib json accepts them with
        # allow_nan=True by default; we reject them as non-RFC.)
        if opts.nan_inf:
            bad = _find_nan_or_inf(value)
            if bad is not None:
                yield from emit(Issue(
                    line=lineno,
                    column=None,
                    code="nan-inf",
                    message=f"value contains non-RFC numeric literal: {bad}",
                ))
                if opts.max_issues and issued >= opts.max_issues:
                    return

        # required keys (only meaningful for top-level objects)
        if opts.required_keys and isinstance(value, dict):
            missing = [k for k in opts.required_keys if k not in value]
            if missing:
                yield from emit(Issue(
                    line=lineno,
                    column=None,
                    code="missing-keys",
                    message=f"missing required object key(s): {', '.join(missing)}",
                ))
                if opts.max_issues and issued >= opts.max_issues:
                    return

        # homogeneous top-level type
        if opts.homogeneous:
            tl = _top_level_kind(value)
            if seen_top_level is None:
                seen_top_level = tl
            elif tl != seen_top_level:
                yield from emit(Issue(
                    line=lineno,
                    column=None,
                    code="heterogeneous",
                    message=(
                        f"top-level type {tl!r} differs from earlier {seen_top_level!r}"
                    ),
                ))
                if opts.max_issues and issued >= opts.max_issues:
                    return

    # end-of-file checks
    if saw_any_line and opts.final_newline and not last_ended_with_newline:
        yield Issue(
            line=lineno,  # last lineno seen
            column=None,
            code="no-final-newline",
            message="file does not end with a newline",
            severity=Severity.WARNING,
        )


def check_path(path: PathLike, *, options: Optional[Options] = None) -> Iterator[Issue]:
    """Open a path (auto-detecting .gz) and yield Issue records."""
    with _open_text(path) as fh:
        yield from check_stream(fh, options=options)


# ---------- helpers ----------

def _top_level_kind(v: object) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def _find_nan_or_inf(v: object) -> Optional[str]:
    """Walk the parsed value; return a description of the first NaN/Inf found,
    or None. Uses an explicit stack to avoid deep recursion."""
    stack = [v]
    while stack:
        node = stack.pop()
        if isinstance(node, float):
            if node != node:  # NaN
                return "NaN"
            if node == float("inf"):
                return "Infinity"
            if node == float("-inf"):
                return "-Infinity"
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None
