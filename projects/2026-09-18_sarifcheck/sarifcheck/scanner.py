"""File-system scanner for sarifcheck.

Walks a file or a directory, applies the rule table to every SARIF file
found, and returns one ScanResult. Every failure mode on the way in - a
missing file, an oversized file, bad UTF-8, JSON that does not parse, a
top-level value that is not an object - becomes a structured diagnostic
rather than a traceback.
"""

from __future__ import annotations

import fnmatch
import os
import zlib
from typing import FrozenSet, List, Sequence, Tuple

from .parse import (
    PositionLookup,
    build_index,
    decode_bytes,
    load_json_document,
)
from .rules import ALL_RULES, run_rules
from .types import Finding, Options, RuleContext, ScanResult


DEFAULT_GLOBS: Tuple[str, ...] = ("*.sarif", "*.sarif.json")

# A real monorepo scan can emit hundreds of megabytes of SARIF. json.load
# would exhaust memory before a single rule ran, so refuse above a budget
# and say so, rather than dying with MemoryError.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FILES = 1000

# zlib level 6 matches the common gzip default closely enough to judge a
# payload against a documented compressed-size ceiling.
_COMPRESS_LEVEL = 6


def _matches_any(name: str, globs: Sequence[str]) -> bool:
    lowered = name.lower()
    for pattern in globs:
        if fnmatch.fnmatchcase(lowered, pattern.lower()):
            return True
    return False


def discover(
    root: str,
    globs: Sequence[str] = DEFAULT_GLOBS,
    max_files: int = DEFAULT_MAX_FILES,
) -> List[str]:
    """Discover SARIF files under `root`.

    A path given directly on the command line is scanned whatever it is
    named, so `sarifcheck results.json` works. A directory walk applies the
    globs. Symlinked directories are not followed.
    """
    if not os.path.exists(root):
        return []
    if os.path.isfile(root):
        return [root]
    hits: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            if _matches_any(name, globs):
                hits.append(os.path.join(dirpath, name))
                if len(hits) >= max_files:
                    return hits
    return hits


def _wants_compressed_size(options: Options) -> bool:
    for rule in ALL_RULES:
        if rule.id != "SRF-023":
            continue
        if rule.id in options.disabled:
            return False
        return rule.profile.value in options.profiles
    return False  # pragma: no cover - SRF-023 is always in the table


def compressed_size(raw: bytes) -> int:
    """gzip-equivalent compressed length of `raw`, in bytes."""
    compressor = zlib.compressobj(_COMPRESS_LEVEL, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    total = len(compressor.compress(raw))
    total += len(compressor.flush())
    return total


def scan_file(
    path: str,
    options: Options,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Tuple[List[Finding], List[str], List[str], bool]:
    """Scan one file.

    Returns (findings, errors, notes, partial). `errors` non-empty means the
    file could not be analysed at all, which the caller turns into verdict
    unknown and exit code 2.
    """
    errors: List[str] = []
    notes: List[str] = []
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return [], ["read-error: " + path + ": " + str(exc)], notes, False
    if size > max_bytes:
        return [], [
            "size-refused: " + path + ": " + str(size) + " bytes exceeds the "
            "--max-bytes budget of " + str(max_bytes) + "; raise --max-bytes to "
            "parse it, or split the report"
        ], notes, False
    try:
        with open(path, "rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        return [], ["read-error: " + path + ": " + str(exc)], notes, False
    if len(raw) > max_bytes:  # pragma: no cover - raced growth
        return [], [
            "size-refused: " + path + ": grew past the --max-bytes budget of "
            + str(max_bytes) + " while being read"
        ], notes, False

    text, decode_error = decode_bytes(raw)
    if text is None:
        return [], ["decode-error: " + path + ": " + str(decode_error)], notes, False

    doc, parse_error, duplicates = load_json_document(text)
    if parse_error is not None:
        return [], ["parse-error: " + path + ": " + parse_error], notes, False
    if not isinstance(doc, dict):
        return [], [
            "shape-error: " + path + ": top-level JSON value is "
            + type(doc).__name__ + ", not an object; a SARIF file's root must be "
            "a JSON object"
        ], notes, False
    if not isinstance(doc.get("runs"), list):
        return [], [
            "shape-error: " + path + ": no top-level 'runs' array; this does not "
            "look like a SARIF file, so no rule could be applied to it"
        ], notes, False
    if duplicates:
        unique = sorted(set(duplicates))
        notes.append(
            "duplicate-keys: " + path + ": " + str(len(duplicates)) + " duplicate "
            "object key(s) (" + ", ".join(unique[:5])
            + ("..." if len(unique) > 5 else "") + "); JSON parsing kept the last "
            "value for each, which is what a consumer will see"
        )

    index = build_index(doc)
    ctx = RuleContext(
        doc=doc,
        text=text,
        path=path,
        index=index,
        options=options,
        lookup=PositionLookup(text),
        compressed_bytes=compressed_size(raw) if _wants_compressed_size(options) else -1,
        raw_bytes=len(raw),
    )
    try:
        findings = run_rules(ctx)
    except RecursionError:  # pragma: no cover - traversal is iterative
        return [], [
            "traversal-error: " + path + ": nesting exceeded the recursion limit "
            "during rule evaluation"
        ], notes, False
    return findings, errors, notes, index.any_external_property_files


def scan_path(
    root: str,
    options: Options,
    globs: Sequence[str] = DEFAULT_GLOBS,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ScanResult:
    files = discover(root, globs=globs, max_files=max_files)
    all_findings: List[Finding] = []
    errors: List[str] = []
    notes: List[str] = []
    partial = False
    for path in files:
        found, file_errors, file_notes, file_partial = scan_file(
            path, options, max_bytes=max_bytes
        )
        all_findings.extend(found)
        errors.extend(file_errors)
        notes.extend(file_notes)
        partial = partial or file_partial
    all_findings.sort(key=lambda f: f.sort_key())
    return ScanResult(
        files_scanned=len(files),
        findings=tuple(all_findings),
        errors=tuple(errors),
        notes=tuple(notes),
        partial=partial,
    )


def build_options(
    limits: dict,
    profiles: FrozenSet[str],
    disabled: FrozenSet[str],
    ignore_rule_ids: FrozenSet[str] = frozenset(),
    allow_path_in_message: bool = False,
    show_matches: bool = False,
) -> Options:
    return Options(
        limits=dict(limits),
        profiles=profiles,
        disabled=disabled,
        ignore_rule_ids=ignore_rule_ids,
        allow_path_in_message=allow_path_in_message,
        show_matches=show_matches,
    )
