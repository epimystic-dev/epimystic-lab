"""Text and JSON parsing helpers.

The primary anchor for a finding is a JSON property path. As a convenience
we also report a line and column, computed by locating the value's textual
position in the raw file text. When the position cannot be resolved with
confidence the line/column fall back to (1, 1) so the finding remains
emittable and deterministic.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

BOM = "\ufeff"


def read_text(path: str, max_bytes: int) -> str:
    """Read a file as text.

    UTF-8 is tried first with the BOM stripped. Latin-1 is the final
    fallback so a random byte sequence never raises. Bytes past
    max_bytes are truncated; the caller is expected to warn.
    """
    with open(path, "rb") as f:
        raw = f.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    if text.startswith(BOM):
        text = text[len(BOM):]
    return text


def load_json(text: str) -> Tuple[Optional[Any], Optional[str]]:
    """Return (doc, err). doc is None on failure."""
    try:
        return json.loads(text), None
    except json.JSONDecodeError as e:
        return None, f"json decode error: {e.msg} at line {e.lineno} col {e.colno}"


def offset_to_line_col(text: str, offset: int) -> Tuple[int, int]:
    """Convert a byte offset into a 1-based (line, column).

    An offset outside the text collapses to the last line/column.
    Line separators are counted as LF; CR is ignored so a CRLF file
    still reports the same line numbers a text editor shows.
    """
    if offset < 0:
        return (1, 1)
    if offset > len(text):
        offset = len(text)
    line = 1
    col_start = 0
    for i, ch in enumerate(text[:offset]):
        if ch == "\n":
            line += 1
            col_start = i + 1
    col = offset - col_start + 1
    if col < 1:
        col = 1
    return (line, col)


def find_key(text: str, key: str, from_offset: int = 0) -> int:
    """Return the offset of the first `"key"` occurrence at or after
    from_offset, or -1 if not found. This is a shape-only search - it
    does not try to be a full JSON tokenizer, and is only used to give
    a finding a rough textual anchor after the rule has already run
    against the parsed object.
    """
    needle = '"' + key + '"'
    idx = text.find(needle, max(0, from_offset))
    return idx


def find_string_value(text: str, value: str, from_offset: int = 0) -> int:
    """Return the offset of the first exact string literal occurrence
    of value at or after from_offset, or -1 if not found. Handles
    only escape-free strings; a caller with an escape-heavy value
    should fall back to key location.
    """
    if not value:
        return -1
    idx = text.find('"' + value + '"', max(0, from_offset))
    return idx


def truncate_snippet(text: str, limit: int = 160) -> str:
    """Truncate a snippet for display; newlines become spaces."""
    if len(text) > limit:
        text = text[:limit] + "..."
    return text.replace("\n", " ").replace("\r", " ")


def is_object(x: Any) -> bool:
    return isinstance(x, dict)


def get_object(doc: Any, key: str) -> Dict[str, Any]:
    v = doc.get(key) if is_object(doc) else None
    return v if is_object(v) else {}


def iter_dependency_sections(doc: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """Return the dependency-shaped subobjects present on doc, in a
    fixed order. Every value observed by rules is treated as a string
    version specifier; non-string values are simply ignored.
    """
    if not is_object(doc):
        return []
    out: List[Tuple[str, Dict[str, Any]]] = []
    for name in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        v = doc.get(name)
        if is_object(v):
            out.append((name, v))
    return out


LIFECYCLE_HOOKS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preprepare",
    "prepublishOnly",
    "prepack",
    "postpack",
)


def iter_lifecycle_hooks(doc: Any) -> List[Tuple[str, str]]:
    """Return (hook_name, command_string) pairs across scripts.

    Only entries whose value is a string are considered. Anything else
    is a package.json shape defect that a schema validator already
    flags and is out of scope here.
    """
    scripts = get_object(doc, "scripts")
    out: List[Tuple[str, str]] = []
    for hook in LIFECYCLE_HOOKS:
        cmd = scripts.get(hook)
        if isinstance(cmd, str):
            out.append((hook, cmd))
    return out
