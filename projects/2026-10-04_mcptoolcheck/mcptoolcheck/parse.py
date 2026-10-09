"""File-shape parser for mcptoolcheck.

Four tool-descriptor file shapes are supported, matching what shows up
in the wild on the MCP tool-advertisement surface:

  (a) A ``tools/list`` response snapshot:
        {"tools": [{"name": "...", "description": "...", ...}, ...]}

  (b) A bare array:
        [{"name": "...", "description": "...", ...}, ...]

  (c) A dict keyed by tool name:
        {"my_tool": {"description": "...", "inputSchema": {...}}, ...}

  (d) A single tool-descriptor object:
        {"name": "...", "description": "...", ...}

Load returns the raw document and a per-tool list of
``(logical_path, tool_dict)`` pairs so rules can anchor findings on an
unambiguous JSON pointer and name.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional, Tuple


def load_json(content: str) -> Tuple[Optional[Any], Optional[str]]:
    """Parse JSON text. Returns (doc, error-message)."""
    try:
        return json.loads(content), None
    except json.JSONDecodeError as e:
        return None, f"invalid JSON at line {e.lineno} column {e.colno}: {e.msg}"


def _looks_like_tool(d: dict) -> bool:
    """A dict is a tool descriptor if it has (name AND description) or
    (inputSchema / input_schema / annotations) alongside a description.
    """
    if not isinstance(d, dict):
        return False
    if "name" in d and "description" in d:
        return True
    if "description" in d and any(
        k in d for k in ("inputSchema", "input_schema", "annotations")
    ):
        return True
    return False


def extract_tools(doc: Any) -> List[Tuple[str, dict]]:
    """Return a list of ``(json-pointer, tool-dict)`` pairs. The pointer
    is a human-readable path, not a strict RFC-6901 pointer.
    """
    if isinstance(doc, list):
        out: List[Tuple[str, dict]] = []
        for i, item in enumerate(doc):
            if isinstance(item, dict) and _looks_like_tool(item):
                out.append((f"[{i}]", item))
        return out

    if not isinstance(doc, dict):
        return []

    if "tools" in doc and isinstance(doc["tools"], list):
        out = []
        for i, item in enumerate(doc["tools"]):
            if isinstance(item, dict) and _looks_like_tool(item):
                out.append((f"tools[{i}]", item))
        return out

    if _looks_like_tool(doc):
        return [("<root>", doc)]

    out = []
    for key, value in doc.items():
        if isinstance(value, dict) and (
            "description" in value
            or "inputSchema" in value
            or "input_schema" in value
            or "annotations" in value
        ):
            synth = dict(value)
            synth.setdefault("name", key)
            out.append((key, synth))
    return out


def tool_name(tool: dict, fallback: str) -> str:
    """Return a safe display name for a tool descriptor."""
    n = tool.get("name")
    if isinstance(n, str) and n:
        return n
    return fallback


def tool_description(tool: dict) -> str:
    """Return the tool's description string, or empty string."""
    d = tool.get("description")
    return d if isinstance(d, str) else ""


def tool_input_schema(tool: dict) -> Optional[dict]:
    """Return the tool's inputSchema (preferring camelCase MCP spelling)."""
    for key in ("inputSchema", "input_schema"):
        s = tool.get(key)
        if isinstance(s, dict):
            return s
    return None


def tool_annotations(tool: dict) -> dict:
    """Return a flat view of annotation hints.

    MCP tools can carry annotations either as a nested
    ``annotations`` object or as sibling fields (``readOnlyHint``,
    ``destructiveHint``). This flattens both into one dict so a rule
    can read a single surface.
    """
    out: dict = {}
    ann = tool.get("annotations")
    if isinstance(ann, dict):
        out.update(ann)
    for key in ("readOnlyHint", "destructiveHint", "idempotentHint",
                "openWorldHint"):
        if key in tool and key not in out:
            out[key] = tool[key]
    return out


__all__ = [
    "load_json",
    "extract_tools",
    "tool_name",
    "tool_description",
    "tool_input_schema",
    "tool_annotations",
]
