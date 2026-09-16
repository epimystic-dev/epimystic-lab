"""File-system scanner for mcpservercheck."""

import fnmatch
import os
from dataclasses import replace
from typing import List, Sequence

from .parse import iter_jsonl, load_json_or_none, strip_bom
from .rules import run_rules
from .types import Finding, ScanResult


DEFAULT_GLOBS = ("*.json", "*.jsonl", "mcp.json", ".mcp.json")
DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_BYTES = 1 * 1024 * 1024


def read_text(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """Read a text file with size cap and encoding fallback."""
    with open(path, "rb") as f:
        raw = f.read(max_bytes)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return strip_bom(text)


def _matches_any(name: str, globs: Sequence[str]) -> bool:
    lname = name.lower()
    for pat in globs:
        if fnmatch.fnmatchcase(lname, pat.lower()):
            return True
    return False


def discover(root: str, globs: Sequence[str] = DEFAULT_GLOBS, max_files: int = DEFAULT_MAX_FILES) -> List[str]:
    """Discover files under `root` that match the file globs."""
    if not os.path.exists(root):
        return []
    if os.path.isfile(root):
        if _matches_any(os.path.basename(root), globs):
            return [root]
        return []
    hits: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            if _matches_any(fn, globs):
                hits.append(os.path.join(dirpath, fn))
                if len(hits) >= max_files:
                    return hits
    return hits


def scan_file(path: str, disabled=frozenset(), max_bytes: int = DEFAULT_MAX_BYTES):
    """Scan a single file. Returns (findings, error_or_None)."""
    try:
        text = read_text(path, max_bytes=max_bytes)
    except OSError as e:
        return [], "read-error: " + path + ": " + str(e)
    findings: List[Finding] = []
    if path.lower().endswith(".jsonl"):
        for lineno, obj in iter_jsonl(text):
            per = run_rules(obj, text, path, disabled=disabled)
            for f in per:
                findings.append(replace(f, line=lineno))
        return findings, None
    parsed = load_json_or_none(text)
    if parsed is None:
        return findings, None
    findings = run_rules(parsed, text, path, disabled=disabled)
    return findings, None


def scan_path(root: str, globs: Sequence[str] = DEFAULT_GLOBS, disabled=frozenset(),
              max_files: int = DEFAULT_MAX_FILES, max_bytes: int = DEFAULT_MAX_BYTES) -> ScanResult:
    files = discover(root, globs=globs, max_files=max_files)
    all_findings: List[Finding] = []
    errors: List[str] = []
    for p in files:
        fs, err = scan_file(p, disabled=disabled, max_bytes=max_bytes)
        all_findings.extend(fs)
        if err:
            errors.append(err)
    all_findings.sort(key=lambda f: f.sort_key())
    return ScanResult(
        files_scanned=len(files),
        findings=tuple(all_findings),
        errors=tuple(errors),
    )
