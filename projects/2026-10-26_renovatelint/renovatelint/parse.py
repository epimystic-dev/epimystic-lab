"""File-shape parser for renovatelint.

Renovate's config file is JSON5-ish in practice (JSONC - plain JSON plus
``//`` and ``/* ... */`` comments plus trailing commas). The .json5
extension additionally allows single-quoted strings and unquoted keys;
we support only the JSONC superset of plain JSON, which is enough for
the vast majority of real-world renovate configs. Files that use the
richer JSON5 features will surface a structured parse error.

The stripping is character-oriented and string-aware (comment markers
inside a string literal are left alone).
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional, Tuple


def strip_jsonc(text: str) -> str:
    """Return ``text`` with JSONC comments and trailing commas removed."""
    out = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j < 0:
                i = n
            else:
                out.append("\n")
                i = j + 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                i = n
            else:
                for k in range(i, j + 2):
                    if text[k] == "\n":
                        out.append("\n")
                i = j + 2
            continue
        out.append(ch)
        i += 1
    stripped = "".join(out)
    return _strip_trailing_commas(stripped)


def _strip_trailing_commas(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "]}":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def load_text(content: str, path: str) -> Tuple[Optional[Any], Optional[str]]:
    """Parse a renovate config file (JSONC-aware).

    Returns (document, error). On error ``document`` is None.

    When the path ends in ``package.json`` and the document carries a
    top-level ``renovate`` key, we unwrap and return just the renovate
    sub-document; everything else is treated as the document itself.
    """
    stripped = strip_jsonc(content)
    try:
        doc = json.loads(stripped)
    except json.JSONDecodeError as e:
        return None, (
            "invalid JSON at line " + str(e.lineno) + " column "
            + str(e.colno) + ": " + e.msg
        )
    base = os.path.basename(path).lower()
    if base == "package.json" and isinstance(doc, dict):
        inner = doc.get("renovate")
        if isinstance(inner, dict):
            return inner, None
        return None, (
            "package.json has no top-level 'renovate' object"
        )
    return doc, None


# minimumReleaseAge is expressed as a human-readable duration string
# understood by Renovate's internal `ms`-style parser. We support the
# documented units; anything we cannot parse returns None so the rule
# treats it as "set but unparseable" rather than "below threshold".
_DURATION_UNITS = {
    "second": 1.0 / 86400,
    "seconds": 1.0 / 86400,
    "minute": 1.0 / 1440,
    "minutes": 1.0 / 1440,
    "hour": 1.0 / 24,
    "hours": 1.0 / 24,
    "day": 1.0,
    "days": 1.0,
    "week": 7.0,
    "weeks": 7.0,
    "month": 30.0,
    "months": 30.0,
    "year": 365.0,
    "years": 365.0,
}


def parse_duration_days(value: Any) -> Optional[float]:
    """Return the duration in days, or None if value is not a string we
    can parse. The value is case-insensitive and tolerates extra spaces.
    """
    if not isinstance(value, str):
        return None
    s = value.strip().lower()
    if not s:
        return None
    # Accept "7d", "14d", "72h" as compact forms.
    compact_units = {"s": 1.0 / 86400, "m": 1.0 / 1440, "h": 1.0 / 24,
                     "d": 1.0, "w": 7.0, "mo": 30.0, "y": 365.0}
    for suffix, factor in sorted(compact_units.items(), key=lambda kv: -len(kv[0])):
        if s.endswith(suffix):
            head = s[: -len(suffix)].strip()
            try:
                return float(head) * factor
            except ValueError:
                continue
    parts = s.split()
    if len(parts) == 2:
        head, unit = parts
        try:
            n = float(head)
        except ValueError:
            return None
        factor = _DURATION_UNITS.get(unit)
        if factor is None:
            return None
        return n * factor
    return None


__all__ = ["strip_jsonc", "load_text", "parse_duration_days"]
