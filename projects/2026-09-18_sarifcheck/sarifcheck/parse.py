"""Stdlib-only parsing helpers for SARIF files.

Three jobs live here:

1. Decoding and parsing a SARIF file with a clean diagnostic instead of a
   traceback on every adversarial shape (bad UTF-8, not JSON at all, wrong
   top-level type, deeply nested, duplicate keys, null bytes).
2. Mapping a JSON property path such as
   "runs[0].results[2].message.text" back onto a line and column, so a
   finding is navigable in an editor. This is done with a small JSON
   tokenizer over the raw text, built lazily and only when there is at
   least one finding to place.
3. The URI and host-layout SHAPE helpers the rules share. Note the word
   shape: these functions recognise textual patterns. A match is never
   evidence that anything sensitive was exposed.

No network, no subprocess, no third-party imports.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote

from .types import DocIndex, RunIndex


BOM = "\ufeff"

MAX_INDEX_TOKENS = 4000000
MAX_INDEX_ENTRIES = 400000


def strip_bom(text: str) -> str:
    if text.startswith(BOM):
        return text[1:]
    return text


_SHORT_LIMIT = 120


def short(value: Any, limit: int = _SHORT_LIMIT) -> str:
    """Compact single-line summary of a value."""
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"[\r\n\t]+", " ", text)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# decoding and parsing
# ---------------------------------------------------------------------------


def decode_bytes(raw: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Decode file bytes as UTF-8. Returns (text, error_message)."""
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return None, "input looks like UTF-16 (BOM present); SARIF files are UTF-8"
    try:
        return strip_bom(raw.decode("utf-8")), None
    except UnicodeDecodeError as exc:
        return None, (
            "input is not valid UTF-8 at byte " + str(exc.start) + ": " + exc.reason
        )


def load_json_document(text: str) -> Tuple[Any, Optional[str], List[str]]:
    """Parse JSON text.

    Returns (obj, error_message, duplicate_key_paths). `obj` is None when
    parsing failed. Never raises: a JSONDecodeError becomes a line/column
    diagnostic, and the RecursionError raised by deeply nested input
    becomes its own message rather than a traceback.
    """
    duplicates: List[str] = []

    def hook(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                duplicates.append(str(key))
            out[key] = value
        return out

    try:
        obj = json.loads(text, object_pairs_hook=hook)
    except json.JSONDecodeError as exc:
        return None, (
            "invalid JSON at line " + str(exc.lineno) + " column "
            + str(exc.colno) + ": " + exc.msg
        ), duplicates
    except RecursionError:
        return None, (
            "JSON nesting exceeds the interpreter recursion limit; refusing "
            "to parse this file"
        ), duplicates
    except (ValueError, TypeError) as exc:
        return None, "invalid JSON: " + str(exc), duplicates
    return obj, None, duplicates


# ---------------------------------------------------------------------------
# position index: JSON property path -> (line, column)
# ---------------------------------------------------------------------------


_WS = " \t\r\n"


def tokenize(text: str, max_tokens: int = MAX_INDEX_TOKENS) -> List[Tuple[str, int, Optional[str]]]:
    """Tokenize already-valid JSON text.

    Returns a list of (kind, offset, string_value). kind is one of
    "{", "}", "[", "]", ",", ":", "str", "lit". Truncates at max_tokens so
    a pathological file cannot exhaust memory here.
    """
    tokens: List[Tuple[str, int, Optional[str]]] = []
    i = 0
    n = len(text)
    while i < n and len(tokens) < max_tokens:
        ch = text[i]
        if ch in _WS:
            i += 1
            continue
        if ch in "{}[],:":
            tokens.append((ch, i, None))
            i += 1
            continue
        if ch == '"':
            start = i
            i += 1
            buf: List[str] = []
            while i < n:
                c = text[i]
                if c == "\\":
                    if i + 1 < n:
                        buf.append(text[i + 1])
                        i += 2
                        continue
                    i += 1
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            tokens.append(("str", start, "".join(buf)))
            continue
        start = i
        while i < n and text[i] not in _WS and text[i] not in "{}[],:":
            i += 1
        if i == start:
            i += 1
        tokens.append(("lit", start, None))
    return tokens


def _join(prefix: str, key: str) -> str:
    if not prefix:
        return key
    return prefix + "." + key


def build_position_index(text: str, max_entries: int = MAX_INDEX_ENTRIES) -> Dict[str, int]:
    """Map every JSON property path in `text` to the offset of its value.

    Paths look like "runs[0].results[2].message.text". The empty string is
    the document root. The index is best effort: it is built from a token
    walk of text that json.loads has already accepted, and it stops early
    once max_entries paths have been recorded, so a very large file gets a
    partial index rather than an out-of-memory failure. A path that is not
    in the index reports position 1:1, which is the documented fallback.
    """
    positions: Dict[str, int] = {}
    tokens = tokenize(text)
    if not tokens:
        return positions

    # frames: (kind, base_path, array_index)
    frames: List[List[Any]] = []
    path = ""
    state = "value"
    pending_key: Optional[str] = None

    for kind, offset, value in tokens:
        if len(positions) >= max_entries:
            break
        if state == "value":
            if kind == "{":
                if path not in positions:
                    positions[path] = offset
                frames.append(["obj", path, 0])
                state = "key_or_end"
                continue
            if kind == "[":
                if path not in positions:
                    positions[path] = offset
                frames.append(["arr", path, 0])
                path = path + "[0]"
                state = "value"
                continue
            if kind == "]":
                # empty array
                if frames and frames[-1][0] == "arr":
                    path = frames[-1][1]
                    frames.pop()
                state = "after"
                continue
            if kind in ("str", "lit"):
                if path not in positions:
                    positions[path] = offset
                state = "after"
                continue
            continue
        if state == "key_or_end":
            if kind == "}":
                if frames and frames[-1][0] == "obj":
                    path = frames[-1][1]
                    frames.pop()
                state = "after"
                continue
            if kind == "str":
                pending_key = value or ""
                state = "colon"
                continue
            continue
        if state == "colon":
            if kind == ":":
                base = frames[-1][1] if frames else ""
                path = _join(base, pending_key or "")
                state = "value"
            continue
        if state == "after":
            if kind == ",":
                if frames and frames[-1][0] == "arr":
                    frames[-1][2] += 1
                    path = frames[-1][1] + "[" + str(frames[-1][2]) + "]"
                    state = "value"
                elif frames and frames[-1][0] == "obj":
                    state = "key"
                continue
            if kind in ("}", "]"):
                if frames:
                    path = frames[-1][1]
                    frames.pop()
                state = "after"
                continue
            continue
        if state == "key":
            if kind == "str":
                pending_key = value or ""
                state = "colon"
                continue
            if kind == "}":
                if frames:
                    path = frames[-1][1]
                    frames.pop()
                state = "after"
                continue
            continue
    return positions


def offset_to_line_col(text: str, offset: int) -> Tuple[int, int]:
    """Convert a character offset into a 1-indexed (line, column)."""
    if offset < 0:
        offset = 0
    if offset > len(text):
        offset = len(text)
    prefix = text[:offset]
    line = prefix.count("\n") + 1
    if line == 1:
        column = offset + 1
    else:
        column = offset - prefix.rfind("\n")
    return line, column


class PositionLookup:
    """Lazy line/column lookup for JSON property paths."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._index: Optional[Dict[str, int]] = None

    def locate(self, prop: str) -> Tuple[int, int]:
        if self._index is None:
            try:
                self._index = build_position_index(self._text)
            except (MemoryError, RecursionError):  # pragma: no cover - guard
                self._index = {}
        offset = self._index.get(prop)
        if offset is None:
            return 1, 1
        return offset_to_line_col(self._text, offset)


# ---------------------------------------------------------------------------
# URI shape helpers
# ---------------------------------------------------------------------------


_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def uri_scheme(uri: str) -> str:
    if not isinstance(uri, str):
        return ""
    match = _SCHEME_RE.match(uri)
    if match is None:
        return ""
    return match.group(1).lower()


def absolute_uri_shape(uri: str) -> str:
    """Classify the absoluteness shape of a uri, or "" when relative.

    Shapes returned:
      "unc"            - starts with two backslashes (\\\\server\\share)
      "windows-drive"  - starts with a drive letter, or file:///C:/...
      "file-scheme"    - file:// URI without a drive letter
      "posix-absolute" - starts with a single / (no scheme)
      "network-scheme" - http/https/ftp and friends: absolute, but not a
                         filesystem path; rules treat this separately
    """
    if not isinstance(uri, str) or not uri:
        return ""
    if uri.startswith("\\\\"):
        return "unc"
    if _DRIVE_RE.match(uri):
        return "windows-drive"
    scheme = uri_scheme(uri)
    if scheme == "file":
        rest = uri[len("file:"):]
        while rest.startswith("/"):
            rest = rest[1:]
        if _DRIVE_RE.match(rest) or re.match(r"^[A-Za-z][:|]", rest):
            return "windows-drive"
        return "file-scheme"
    if scheme:
        return "network-scheme"
    if uri.startswith("/"):
        return "posix-absolute"
    return ""


FILESYSTEM_ABSOLUTE_SHAPES = ("unc", "windows-drive", "file-scheme", "posix-absolute")


def is_filesystem_absolute(uri: str) -> bool:
    return absolute_uri_shape(uri) in FILESYSTEM_ABSOLUTE_SHAPES


def uri_reference_defects(uri: str) -> List[Tuple[str, int]]:
    """Return (defect_name, offset) for things that make `uri` not a URI reference.

    Checked: a backslash separator (native Windows separator where a URI is
    required), a raw unescaped space, and a raw control character. Each is
    reported once, at its first offset.
    """
    out: List[Tuple[str, int]] = []
    if not isinstance(uri, str) or not uri:
        return out
    if uri.startswith("\\\\"):
        out.append(("unc-backslash-prefix", 0))
    else:
        idx = uri.find("\\")
        if idx >= 0:
            out.append(("backslash-separator", idx))
    idx = uri.find(" ")
    if idx >= 0:
        out.append(("unescaped-space", idx))
    match = _CONTROL_RE.search(uri)
    if match is not None:
        out.append(("control-character", match.start()))
    return out


_HOME_PATTERNS = (
    ("posix-home", re.compile(r"/home/([A-Za-z0-9._\-]{1,64})(?=[/\\]|$)")),
    ("macos-home", re.compile(r"/Users/([A-Za-z0-9._\-]{1,64})(?=[/\\]|$)")),
    ("windows-home", re.compile(r"[\\/]Users[\\/]([A-Za-z0-9._\-]{1,64})(?=[\\/]|$)")),
    ("posix-root-home", re.compile(r"/root(?=[/\\]|$)")),
)


def home_segment_shape(value: str) -> Optional[Tuple[str, int, int]]:
    """Find a home-directory-SHAPED segment in `value`.

    Returns (shape_name, offset, account_segment_length) or None. The
    account segment itself is deliberately NOT returned: callers report the
    shape and the length, never the text. Percent-encoded input is decoded
    first so that /home/%64evuser is seen the same way as /home/devuser.
    """
    if not isinstance(value, str) or not value:
        return None
    candidates = [value]
    if "%" in value:
        try:
            decoded = unquote(value)
        except (UnicodeDecodeError, ValueError):  # pragma: no cover - guard
            decoded = value
        if decoded != value:
            candidates.append(decoded)
    for candidate in candidates:
        for name, pattern in _HOME_PATTERNS:
            match = pattern.search(candidate)
            if match is not None:
                groups = match.groups()
                seg_len = len(groups[0]) if groups else 0
                return name, match.start(), seg_len
    return None


_PATH_IN_TEXT_PATTERNS = (
    ("windows-drive-path", re.compile(r"[A-Za-z]:[\\/][^\s\"'<>|]{1,400}")),
    ("unc-path", re.compile(r"\\\\[A-Za-z0-9._\-]{1,64}\\[^\s\"'<>|]{1,400}")),
    ("file-uri", re.compile(r"file:///[^\s\"'<>|]{0,400}")),
    ("posix-home", re.compile(r"/home/[A-Za-z0-9._\-]{1,64}(?=[/\\]|\s|$)")),
    ("macos-home", re.compile(r"/Users/[A-Za-z0-9._\-]{1,64}(?=[/\\]|\s|$)")),
    ("posix-root-home", re.compile(r"/root(?=[/\\]|\s|$)")),
)


def host_layout_matches(value: str, limit: int = 50) -> List[Tuple[str, int, int]]:
    """Find host-layout path SHAPES in free text.

    Returns up to `limit` tuples of (shape_name, offset, match_length),
    sorted by offset. A match is a string shape. It is not proof that a
    path was published, that the segment is an account name, or that
    anything sensitive was exposed.
    """
    out: List[Tuple[str, int, int]] = []
    if not isinstance(value, str) or not value:
        return out
    for name, pattern in _PATH_IN_TEXT_PATTERNS:
        for match in pattern.finditer(value):
            out.append((name, match.start(), len(match.group(0))))
            if len(out) >= limit * len(_PATH_IN_TEXT_PATTERNS):
                break
    out.sort(key=lambda item: (item[1], item[0]))
    return out[:limit]


_TOKEN_SHAPE_RE = re.compile(r"[A-Za-z0-9+/_\-]{40,}={0,2}")


def token_shaped_runs(value: str, min_distinct: int = 16, limit: int = 10) -> List[Tuple[int, int]]:
    """Find long opaque base64-ish runs in free text.

    Returns (offset, length) pairs. The matched text is never returned:
    a linter whose own stdout reprints a candidate credential is worse than
    the defect it reports. This finds a SHAPE, not a secret - a long hash,
    a content digest, or a minified identifier all match.
    """
    out: List[Tuple[int, int]] = []
    if not isinstance(value, str) or not value:
        return out
    for match in _TOKEN_SHAPE_RE.finditer(value):
        text = match.group(0)
        if len(set(text)) < min_distinct:
            continue
        if not any(c.isdigit() for c in text):
            continue
        if not any(c.isalpha() for c in text):
            continue
        out.append((match.start(), len(text)))
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# SARIF document index
# ---------------------------------------------------------------------------


def as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def nested_text(container: Any, key: str) -> Optional[str]:
    """Read container[key]["text"] when both layers are the right type."""
    sub = as_dict(container).get(key)
    text = as_dict(sub).get("text")
    return text if isinstance(text, str) else None


def build_index(doc: Any) -> DocIndex:
    """Precompute per-run facts so N rules do not each re-walk the arrays."""
    index = DocIndex()
    runs = as_list(as_dict(doc).get("runs"))
    index.run_count = len(runs)
    for run_pos, run in enumerate(runs):
        run_index = RunIndex(run_index=run_pos)
        run_dict = as_dict(run)
        tool = as_dict(run_dict.get("tool"))
        driver = as_dict(tool.get("driver"))
        driver_rules = as_list(driver.get("rules"))
        run_index.driver_rule_count = len(driver_rules)
        collected: List[Any] = list(driver_rules)
        for extension in as_list(tool.get("extensions")):
            ext_rules = as_list(as_dict(extension).get("rules"))
            run_index.extension_rule_count += len(ext_rules)
            collected.extend(ext_rules)
        run_index.rules = collected
        for pos, rule in enumerate(collected):
            rule_id = as_dict(rule).get("id")
            if isinstance(rule_id, str):
                run_index.rule_ids.append(rule_id)
                if rule_id not in run_index.rule_id_to_pos:
                    run_index.rule_id_to_pos[rule_id] = pos
            else:
                run_index.rule_ids.append(None)
        run_index.has_rule_metadata = len(collected) > 0
        base_ids = run_dict.get("originalUriBaseIds")
        if isinstance(base_ids, dict):
            run_index.uri_base_ids = base_ids
        external = run_dict.get("externalPropertyFileReferences")
        run_index.has_external_property_files = isinstance(external, dict) and bool(external)
        if run_index.has_external_property_files:
            index.any_external_property_files = True
        run_index.results = as_list(run_dict.get("results"))
        index.runs.append(run_index)
    return index


def driver_rules_only(run: Any) -> List[Any]:
    tool = as_dict(as_dict(run).get("tool"))
    return as_list(as_dict(tool.get("driver")).get("rules"))


def iter_result_locations(result: Any, result_path: str) -> List[Tuple[str, Any]]:
    """Bounded, documented walk over the location-bearing paths of a result.

    v1 visits exactly these property paths and no others:

      results[].locations[]
      results[].relatedLocations[]
      results[].analysisTarget                       (an artifactLocation)
      results[].codeFlows[].threadFlows[].locations[].location
      results[].fixes[].artifactChanges[].artifactLocation

    The walk is a flat loop, not recursion: codeFlows and graphs nest
    arbitrarily in SARIF and a recursive walker would raise RecursionError
    on a large or adversarial file, which reads as a crash rather than a
    finding. Returns (property_path, location_object) pairs, where a
    location_object is a SARIF location (it may carry physicalLocation) -
    except for analysisTarget and artifactChanges entries, which are bare
    artifactLocation objects and are returned wrapped so callers can treat
    them uniformly.
    """
    out: List[Tuple[str, Any]] = []
    result_dict = as_dict(result)
    for key in ("locations", "relatedLocations"):
        for pos, loc in enumerate(as_list(result_dict.get(key))):
            out.append((result_path + "." + key + "[" + str(pos) + "]", loc))
    analysis_target = result_dict.get("analysisTarget")
    if isinstance(analysis_target, dict):
        out.append((
            result_path + ".analysisTarget",
            {"physicalLocation": {"artifactLocation": analysis_target}},
        ))
    for flow_pos, code_flow in enumerate(as_list(result_dict.get("codeFlows"))):
        for thread_pos, thread_flow in enumerate(as_list(as_dict(code_flow).get("threadFlows"))):
            for loc_pos, entry in enumerate(as_list(as_dict(thread_flow).get("locations"))):
                inner = as_dict(entry).get("location")
                if not isinstance(inner, dict):
                    continue
                out.append((
                    result_path + ".codeFlows[" + str(flow_pos) + "].threadFlows["
                    + str(thread_pos) + "].locations[" + str(loc_pos) + "].location",
                    inner,
                ))
    for fix_pos, fix in enumerate(as_list(result_dict.get("fixes"))):
        for change_pos, change in enumerate(as_list(as_dict(fix).get("artifactChanges"))):
            artifact_location = as_dict(change).get("artifactLocation")
            if isinstance(artifact_location, dict):
                out.append((
                    result_path + ".fixes[" + str(fix_pos) + "].artifactChanges["
                    + str(change_pos) + "].artifactLocation",
                    {"physicalLocation": {"artifactLocation": artifact_location}},
                ))
    return out


def location_artifact(location: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    """Pull the artifactLocation out of a SARIF location object.

    Returns (artifact_location_or_None, relative_property_suffix).
    """
    loc = as_dict(location)
    physical = as_dict(loc.get("physicalLocation"))
    artifact = physical.get("artifactLocation")
    if isinstance(artifact, dict):
        return artifact, ".physicalLocation.artifactLocation"
    return None, ""


def count_threadflow_locations(result: Any) -> int:
    """Sum thread flow locations across ALL codeFlows of one result.

    The documented ingest ceiling is per result, not per codeFlow. Counting
    per codeFlow would make the limit rule silently useless on exactly the
    large taint-flow files it exists for.
    """
    total = 0
    for code_flow in as_list(as_dict(result).get("codeFlows")):
        for thread_flow in as_list(as_dict(code_flow).get("threadFlows")):
            total += len(as_list(as_dict(thread_flow).get("locations")))
    return total
