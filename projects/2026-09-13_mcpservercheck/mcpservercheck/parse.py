"""Text-position and JSON parsing helpers.

Rules operate on parsed JSON structures for structural correctness, and use
the helpers here to attach a source line and column so a finding is
navigable in an editor.
"""

import json
import re
from typing import Tuple


BOM = "\ufeff"


def offset_to_line_col(text: str, offset: int):
    """Convert a byte offset into a 1-indexed (line, column)."""
    if offset < 0:
        offset = 0
    if offset > len(text):
        offset = len(text)
    prefix = text[:offset]
    line = prefix.count("\n") + 1
    if line == 1:
        col = offset + 1
    else:
        col = offset - prefix.rfind("\n")
    return line, col


def find_key_line_col(text: str, key, from_offset: int = 0):
    """Locate the first occurrence of a JSON key \"<key>\" after from_offset."""
    if key is None:
        return 1, 1
    needle = '"' + str(key) + '"'
    idx = text.find(needle, from_offset)
    if idx < 0:
        return 1, 1
    return offset_to_line_col(text, idx)


def find_value_line_col(text: str, value_repr: str, from_offset: int = 0):
    """Locate the first occurrence of a string value literal in the text."""
    if value_repr is None or value_repr == "":
        return 1, 1
    idx = text.find(value_repr, from_offset)
    if idx < 0:
        return 1, 1
    return offset_to_line_col(text, idx)


def load_json_or_none(text: str):
    """Parse JSON text; return None on failure. Never raises."""
    text = strip_bom(text)
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None


def iter_jsonl(text: str):
    """Iterate parsed JSON objects for each non-empty line of JSONL text."""
    text = strip_bom(text)
    for lineno, raw in enumerate(text.splitlines(), start=1):
        s = raw.strip()
        if not s:
            continue
        try:
            yield lineno, json.loads(s)
        except (ValueError, TypeError, RecursionError):
            continue


def strip_bom(text: str) -> str:
    if text.startswith(BOM):
        return text[1:]
    return text


_SHORT_LIMIT = 120


def short(s, limit: int = _SHORT_LIMIT) -> str:
    """Compact single-line summary of a value for finding.snippet."""
    if s is None:
        return ""
    s = str(s)
    s = re.sub(r"[\r\n\t]+", " ", s)
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."
