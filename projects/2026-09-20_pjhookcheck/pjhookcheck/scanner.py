"""Scanner - discovery + per-file execution."""

from __future__ import annotations

import fnmatch
import os
from typing import Iterable, List, Sequence, Tuple

from .parse import load_json, read_text
from .rules import run_all
from .types import Finding, Options, ScanResult, Severity


DEFAULT_GLOBS: Tuple[str, ...] = (
    "package.json",
    "**/package.json",
)


def _matches_any(name: str, patterns: Sequence[str]) -> bool:
    for pat in patterns:
        # match the tail (relative) name, not just the leaf, so
        # "packages/foo/package.json" also matches "**/package.json".
        if fnmatch.fnmatch(name, pat):
            return True
        # fallback: match the leaf
        if fnmatch.fnmatch(os.path.basename(name), pat):
            return True
    return False


def discover(paths: Iterable[str], globs: Sequence[str], max_files: int) -> List[str]:
    """Expand a list of paths into a sorted, deduplicated list of files.

    A path that is a file is kept verbatim if it matches any glob (or if
    globs is empty). A path that is a directory is walked; each file
    inside is checked against globs. The result is bounded by max_files.
    """
    out: List[str] = []
    seen = set()
    active_globs = tuple(globs) if globs else DEFAULT_GLOBS
    for p in paths:
        if not os.path.exists(p):
            continue
        if os.path.isfile(p):
            if not globs or _matches_any(p, active_globs):
                ap = os.path.abspath(p)
                if ap not in seen:
                    seen.add(ap)
                    out.append(p)
            continue
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in files:
                    rel = os.path.join(root, f)
                    tail = os.path.relpath(rel, p).replace("\\", "/")
                    if _matches_any(tail, active_globs) or _matches_any(f, active_globs):
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


def scan_paths(paths: Sequence[str], globs: Sequence[str], options: Options) -> ScanResult:
    files = discover(paths, globs, options.max_files)
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
