"""Minimal .env parser.

Scope is deliberately narrow: one KEY=VALUE per line, optional `export`
prefix, `#` line comments, single- or double-quoted values on a single
line, and unquoted values with inline `#` comments trimmed. No variable
expansion, no multi-line values, no line continuation. Anything outside
that scope is either flagged as a ParseError or reported verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Tuple

_IDENT_START = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
_IDENT_CONT = _IDENT_START + "0123456789"


@dataclass(frozen=True)
class EnvEntry:
    """One KEY=VALUE assignment parsed from an env file."""

    key: str
    value: str
    line: int
    col: int
    quoted: bool


@dataclass(frozen=True)
class ParseError:
    """A syntax error encountered while parsing an env file."""

    message: str
    line: int
    col: int


def _is_ident(s: str) -> bool:
    if not s:
        return False
    if s[0] not in _IDENT_START:
        return False
    for ch in s[1:]:
        if ch not in _IDENT_CONT:
            return False
    return True


def _split_key_value(rest: str, line_no: int, col_offset: int) -> Tuple[EnvEntry, Optional[ParseError]]:
    """Parse a single logical line (already stripped of `export` prefix).

    Returns (entry_or_placeholder, error_or_None).
    """
    eq = rest.find("=")
    if eq < 0:
        return (
            EnvEntry(key="", value="", line=line_no, col=col_offset + 1, quoted=False),
            ParseError(
                message="missing '=' in assignment",
                line=line_no,
                col=col_offset + 1,
            ),
        )
    key = rest[:eq].rstrip()
    key_col = col_offset + 1
    if not _is_ident(key):
        return (
            EnvEntry(key=key, value="", line=line_no, col=key_col, quoted=False),
            ParseError(
                message=f"invalid identifier {key!r}",
                line=line_no,
                col=key_col,
            ),
        )

    value_raw = rest[eq + 1:]
    value_col = col_offset + eq + 2  # 1-based col of first char of value
    leading = len(value_raw) - len(value_raw.lstrip(" \t"))
    value_col += leading
    value_stripped = value_raw.lstrip(" \t")

    if not value_stripped:
        return (
            EnvEntry(key=key, value="", line=line_no, col=key_col, quoted=False),
            None,
        )

    # `KEY=   # comment` -> empty value (an inline comment separated from
    # the `=` by whitespace never counts as a value). `KEY=#ff00aa` (no
    # whitespace) still counts as a hex-color literal value.
    if leading > 0 and value_stripped.startswith("#"):
        return (
            EnvEntry(key=key, value="", line=line_no, col=key_col, quoted=False),
            None,
        )

    first = value_stripped[0]
    if first in ('"', "'"):
        quote = first
        # Find matching quote on same line
        end = value_stripped.find(quote, 1)
        if end < 0:
            return (
                EnvEntry(key=key, value=value_stripped[1:], line=line_no, col=key_col, quoted=True),
                ParseError(
                    message="unclosed quoted value",
                    line=line_no,
                    col=value_col,
                ),
            )
        val = value_stripped[1:end]
        trailing = value_stripped[end + 1:].strip()
        if trailing and not trailing.startswith("#"):
            return (
                EnvEntry(key=key, value=val, line=line_no, col=key_col, quoted=True),
                ParseError(
                    message="unexpected content after quoted value",
                    line=line_no,
                    col=value_col + end + 1,
                ),
            )
        return (
            EnvEntry(key=key, value=val, line=line_no, col=key_col, quoted=True),
            None,
        )

    # Unquoted: strip trailing whitespace and inline comment (comment must be
    # separated by at least one whitespace char to avoid clipping `#`-in-value
    # like `COLOR=#ff00aa`).
    trimmed = value_stripped.rstrip()
    for i, ch in enumerate(trimmed):
        if ch == "#" and i > 0 and trimmed[i - 1] in " \t":
            trimmed = trimmed[:i].rstrip()
            break
    return (
        EnvEntry(key=key, value=trimmed, line=line_no, col=key_col, quoted=False),
        None,
    )


def parse_env(source: Iterable[str]) -> Tuple[List[EnvEntry], List[ParseError]]:
    """Parse an iterable of raw lines (with or without trailing newlines).

    Returns (entries, errors). Errors are non-fatal: parsing continues past
    any single bad line.
    """
    entries: List[EnvEntry] = []
    errors: List[ParseError] = []

    for line_no, raw in enumerate(source, start=1):
        line = raw.rstrip("\r\n")
        stripped = line.lstrip()
        col_offset = len(line) - len(stripped)
        if not stripped or stripped.startswith("#"):
            continue

        rest = stripped
        if rest.startswith("export ") or rest.startswith("export\t"):
            rest = rest[len("export"):].lstrip()
            col_offset += len(stripped) - len(rest)

        entry, err = _split_key_value(rest, line_no, col_offset)
        if err is not None:
            errors.append(err)
            if not entry.key:
                continue
        entries.append(entry)

    return entries, errors


def iter_parse_env(source: Iterable[str]) -> Iterator[Tuple[Optional[EnvEntry], Optional[ParseError]]]:
    """Streaming variant: yields (entry, error) one line at a time."""
    entries, errors = parse_env(source)
    # For symmetry with per-line iteration, we replay in line-order.
    events: List[Tuple[int, Optional[EnvEntry], Optional[ParseError]]] = []
    for e in entries:
        events.append((e.line, e, None))
    for err in errors:
        events.append((err.line, None, err))
    events.sort(key=lambda t: t[0])
    for _, e, err in events:
        yield (e, err)
