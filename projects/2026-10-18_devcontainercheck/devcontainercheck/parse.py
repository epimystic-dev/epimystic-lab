"""File-shape parser for devcontainercheck.

The Microsoft dev containers specification allows ``devcontainer.json``
to be JSONC - JSON with ``//`` and ``/* ... */`` comments and trailing
commas - and the Visual Studio Code implementation accepts both JSONC
and plain JSON. We therefore strip comments and trailing commas before
delegating to ``json.loads``. The stripping is character-oriented and
string-aware (comment markers inside a string literal are left alone).

Returns the top-level object (or ``None`` on failure) and an error
message describing the parse failure, if any.
"""

from __future__ import annotations

import json
from typing import Any, Optional, Tuple


def strip_jsonc(text: str) -> str:
    """Return ``text`` with JSONC comments and trailing commas removed.

    - Line comments ``// ...`` (to the next newline) are removed.
    - Block comments ``/* ... */`` are removed.
    - Trailing commas before ``]`` or ``}`` are removed.
    - String literals (``"..."``) are preserved verbatim, including
      escaped quotes.
    """
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
            # Line comment. Replace with a single newline so line
            # numbers in a downstream json.JSONDecodeError still line
            # up with the pre-strip source.
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
                # Preserve any newlines inside the block comment so
                # line numbers downstream still align.
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
    """Remove ``,`` tokens immediately before ``]`` or ``}``.

    Walks the string once, tracking in-string state so a comma inside a
    JSON string literal is not touched.
    """
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
    """Parse devcontainer.json text (JSONC-aware).

    Returns (document, error). On error ``document`` is None.
    """
    stripped = strip_jsonc(content)
    try:
        return json.loads(stripped), None
    except json.JSONDecodeError as e:
        return None, (
            "invalid JSON at line " + str(e.lineno) + " column "
            + str(e.colno) + ": " + e.msg
        )


def coerce_command_strings(value: Any) -> list:
    """Collect command strings from a lifecycle-command value.

    The spec allows a lifecycle command to be a string, an array of
    strings, or an object mapping label to string / array. This
    function returns the flat list of strings, each paired with the
    JSON pointer suffix where it was found.
    """
    out = []
    if isinstance(value, str):
        out.append(("", value))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, str):
                out.append(("[" + str(i) + "]", item))
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                out.append(("." + str(key), item))
            elif isinstance(item, list):
                for i, inner in enumerate(item):
                    if isinstance(inner, str):
                        out.append(("." + str(key) + "[" + str(i) + "]", inner))
    return out


__all__ = ["strip_jsonc", "load_text", "coerce_command_strings"]
