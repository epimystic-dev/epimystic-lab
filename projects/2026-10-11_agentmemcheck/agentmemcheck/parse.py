"""File-shape parser for agentmemcheck.

Three memory-store file shapes are supported, matching what shows up
in the wild for agent long-term memory and session memory records:

  (a) A JSON array of entries:
        [{"id": "...", "content": "...", "source": "...", ...}, ...]

  (b) A JSON object wrapping entries under a known key:
        {"memories": [...], "schema_version": "1.0"}
      Known wrapper keys: ``memories``, ``records``, ``entries``,
      ``facts``, ``history``, ``items``.

  (c) JSONL: one entry per line.

Each entry is a dict with any subset of these fields: ``id``,
``content`` / ``text`` / ``value``, ``source`` / ``origin`` / ``author``
/ ``provenance``, ``role`` / ``scope`` / ``type``, ``timestamp`` /
``created_at`` / ``ts``, ``ttl`` / ``expires_at`` / ``expires``,
``reasoning`` / ``rationale`` / ``why``, ``metadata`` / ``meta``.

Load returns the enclosing document (or ``None`` for JSONL), a
``store_meta`` dict of document-level attributes, and a per-entry list
of ``(pointer, entry_dict)`` pairs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple


WRAPPER_KEYS = ("memories", "records", "entries", "facts", "history", "items")

CONTENT_KEYS = ("content", "text", "value", "body", "message")
SOURCE_KEYS = ("source", "origin", "author", "provenance", "from", "producer")
ROLE_KEYS = ("role", "scope", "type", "kind", "category", "privilege")
TIMESTAMP_KEYS = (
    "timestamp", "created_at", "ts", "time", "when", "written_at",
    "recorded_at",
)
TTL_KEYS = ("ttl", "expires_at", "expires", "expiry", "valid_until",
            "retention")
REASONING_KEYS = ("reasoning", "rationale", "why", "chain_of_thought",
                  "thought", "trace")
ID_KEYS = ("id", "memory_id", "record_id", "key", "uid", "uuid")


def load_text(content: str, path: str) -> Tuple[
    Optional[Any], Dict[str, Any], List[Tuple[str, dict]], Optional[str]
]:
    """Parse memory-store text.

    Returns (doc, store_meta, entries, error). On error ``entries`` is
    empty; on success ``error`` is None.
    """
    # JSONL detection: multiple lines where each non-blank line parses
    # as a JSON object. A single-object input parses as JSON directly;
    # a multi-line array also parses as JSON directly. We only treat as
    # JSONL when the entire content fails whole-JSON parsing AND each
    # non-blank line parses as a JSON object.
    doc, whole_err = _try_load_whole(content)
    if whole_err is None:
        store_meta = _store_meta(doc)
        entries = _extract_entries(doc)
        return doc, store_meta, entries, None

    jsonl_entries, jsonl_err = _try_load_jsonl(content)
    if jsonl_err is None:
        return None, {}, jsonl_entries, None

    return None, {}, [], whole_err


def _try_load_whole(content: str) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return json.loads(content), None
    except json.JSONDecodeError as e:
        return None, (
            "invalid JSON at line " + str(e.lineno) + " column "
            + str(e.colno) + ": " + e.msg
        )


def _try_load_jsonl(content: str) -> Tuple[
    List[Tuple[str, dict]], Optional[str]
]:
    out: List[Tuple[str, dict]] = []
    any_line = False
    for i, raw in enumerate(content.splitlines()):
        line = raw.strip()
        if not line:
            continue
        any_line = True
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            return [], (
                "invalid JSON on line " + str(i + 1) + " column "
                + str(e.colno) + ": " + e.msg
            )
        if not isinstance(obj, dict):
            return [], (
                "line " + str(i + 1) + " is not a JSON object"
            )
        out.append(("line[" + str(i + 1) + "]", obj))
    if not any_line:
        return [], "empty input"
    return out, None


def _store_meta(doc: Any) -> Dict[str, Any]:
    """Document-level attributes a shape check can read. Only present
    when the document is a dict (wrapper form); a bare array has no
    document-level surface, so this returns an empty dict there.
    """
    if not isinstance(doc, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in ("schema_version", "schemaVersion", "version", "revision"):
        if key in doc:
            out[key] = doc[key]
    return out


def _extract_entries(doc: Any) -> List[Tuple[str, dict]]:
    if isinstance(doc, list):
        return _extract_from_list(doc, "")

    if not isinstance(doc, dict):
        return []

    for key in WRAPPER_KEYS:
        value = doc.get(key)
        if isinstance(value, list):
            return _extract_from_list(value, key)

    # A bare single entry object (no wrapper, no array) with
    # memory-entry-shaped fields.
    if _looks_like_entry(doc):
        return [("<root>", doc)]

    return []


def _extract_from_list(items: list, wrapper: str) -> List[Tuple[str, dict]]:
    out: List[Tuple[str, dict]] = []
    prefix = wrapper + "[" if wrapper else "["
    suffix = "]"
    for i, item in enumerate(items):
        if isinstance(item, dict):
            out.append((prefix + str(i) + suffix, item))
    return out


def _looks_like_entry(d: dict) -> bool:
    if not isinstance(d, dict):
        return False
    has_content = any(k in d for k in CONTENT_KEYS)
    has_identity = any(k in d for k in ID_KEYS + SOURCE_KEYS + ROLE_KEYS)
    return has_content and has_identity


def entry_content(entry: dict) -> str:
    """Return the entry's content string (first non-empty match on
    CONTENT_KEYS), or empty string.
    """
    for key in CONTENT_KEYS:
        v = entry.get(key)
        if isinstance(v, str):
            return v
    return ""


def entry_source(entry: dict) -> Optional[str]:
    for key in SOURCE_KEYS:
        v = entry.get(key)
        if isinstance(v, str) and v.strip():
            return v
    # Also look inside metadata / meta.
    for meta_key in ("metadata", "meta"):
        meta = entry.get(meta_key)
        if isinstance(meta, dict):
            for key in SOURCE_KEYS:
                v = meta.get(key)
                if isinstance(v, str) and v.strip():
                    return v
    return None


def entry_role(entry: dict) -> Optional[str]:
    for key in ROLE_KEYS:
        v = entry.get(key)
        if isinstance(v, str) and v.strip():
            return v
    return None


def entry_id(entry: dict, fallback: str) -> str:
    for key in ID_KEYS:
        v = entry.get(key)
        if isinstance(v, (str, int)) and str(v).strip():
            return str(v)
    return fallback


def entry_timestamp(entry: dict) -> Optional[Any]:
    for key in TIMESTAMP_KEYS:
        v = entry.get(key)
        if v is not None:
            return v
    return None


def entry_ttl(entry: dict) -> Optional[Any]:
    for key in TTL_KEYS:
        v = entry.get(key)
        if v is not None:
            return v
    return None


def entry_reasoning(entry: dict) -> Optional[str]:
    for key in REASONING_KEYS:
        v = entry.get(key)
        if isinstance(v, str):
            return v
        if isinstance(v, list):
            parts = [p for p in v if isinstance(p, str)]
            if parts:
                return "\n".join(parts)
    return None


__all__ = [
    "WRAPPER_KEYS",
    "CONTENT_KEYS",
    "SOURCE_KEYS",
    "ROLE_KEYS",
    "TIMESTAMP_KEYS",
    "TTL_KEYS",
    "REASONING_KEYS",
    "ID_KEYS",
    "load_text",
    "entry_content",
    "entry_source",
    "entry_role",
    "entry_id",
    "entry_timestamp",
    "entry_ttl",
    "entry_reasoning",
]
