"""Scanner - discovery + per-file execution."""

from __future__ import annotations

import os
from typing import Iterable, List, Sequence, Tuple

from .parse import load_json, read_text
from .rules import run_all
from .types import Finding, Options, ScanResult


# Candidate file names for directory walks. Anything explicitly passed
# as a file path is also scanned.
DEFAULT_CANDIDATES: Tuple[str, ...] = (
    "settings.json",
    ".mcp.json",
    "mcp.json",
    "tools.json",
    "agent-tools.json",
    "permissions.json",
)


def discover(paths: Iterable[str], max_files: int,
             candidates: Sequence[str] = DEFAULT_CANDIDATES) -> List[str]:
    """Expand paths into a sorted, deduplicated file list.

    A path that is a file is kept verbatim. A path that is a directory
    is walked; each file whose leaf name matches `candidates` is
    included. The result is bounded by max_files.
    """
    out: List[str] = []
    seen = set()
    for p in paths:
        if not os.path.exists(p):
            continue
        if os.path.isfile(p):
            ap = os.path.abspath(p)
            if ap not in seen:
                seen.add(ap)
                out.append(p)
            continue
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in files:
                    if f in candidates:
                        rel = os.path.join(root, f)
                        ap = os.path.abspath(rel)
                        if ap not in seen:
                            seen.add(ap)
                            out.append(rel)
    out.sort()
    if len(out) > max_files:
        out = out[:max_files]
    return out


def scan_file(path: str, options: Options) -> Tuple[List[Finding], List[str]]:
    """Scan one file. Returns (findings, errors)."""
    findings: List[Finding] = []
    errors: List[str] = []
    try:
        text = read_text(path, options.max_bytes)
    except OSError as exc:
        return findings, [f"{path}: cannot read: {exc}"]

    doc, err = load_json(text)
    if err is not None:
        return findings, [f"{path}: {err}"]

    findings.extend(run_all(doc, text, path, options))
    return findings, errors


def scan_paths(paths: Sequence[str], options: Options) -> ScanResult:
    files = discover(paths, options.max_files)
    all_findings: List[Finding] = []
    all_errors: List[str] = []
    for f in files:
        fs, errs = scan_file(f, options)
        all_findings.extend(fs)
        all_errors.extend(errs)
    all_findings.sort(key=Finding.sort_key)
    return ScanResult(
        files_scanned=len(files),
        findings=tuple(all_findings),
        errors=tuple(all_errors),
    )
