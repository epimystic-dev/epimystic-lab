"""Scanner: discover Renovate config files, parse, run rules, roll up."""

from __future__ import annotations

import os
from typing import Iterable, List

from .parse import load_text
from .rules import run_all
from .types import Finding, Options, ScanResult, Severity, Verdict
from .verdict import compute_verdict


_RENOVATE_BASENAMES = (
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
    # package.json carries renovate config under a top-level
    # "renovate" key when developers chose not to split it out.
    "package.json",
)


def _looks_like_target(name: str) -> bool:
    low = name.lower()
    if low in _RENOVATE_BASENAMES:
        return True
    return False


def discover_paths(path: str) -> List[str]:
    """Return the list of concrete renovate config files reachable
    from ``path``.

    If ``path`` is a file, it is returned verbatim (so an explicit
    non-standard filename still gets scanned). If ``path`` is a
    directory, we walk it looking for standard names.
    """
    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        return []
    out: List[str] = []
    for root, _dirs, files in os.walk(path):
        for name in files:
            if _looks_like_target(name):
                out.append(os.path.join(root, name))
    out.sort()
    return out


def scan_text(content: str, path: str, options: Options) -> ScanResult:
    """Scan one renovate config string. ``path`` is the display label."""
    doc, err = load_text(content, path)
    if err is not None:
        # A package.json without a renovate key is not a renovatelint
        # scan target. We treat it as a non-scannable sibling and
        # return UNKNOWN with 0 files_scanned so the caller can skip
        # it without emitting a parse-error diagnostic.
        if "no top-level 'renovate' object" in err:
            return ScanResult(files_scanned=0, verdict=Verdict.UNKNOWN)
        return ScanResult(
            findings=[Finding(
                rule_id="RNV-000",
                severity=Severity.HIGH,
                message=err,
                pointer="<root>",
                path=path,
                hint="file is not valid JSON / JSONC",
            )],
            files_scanned=1,
            verdict=Verdict.UNHEALTHY,
            error=err,
        )
    findings = run_all(doc, path, options)
    r = ScanResult(findings=findings, files_scanned=1)
    r.verdict = compute_verdict(findings, r.files_scanned, options)
    return r


def scan_file(path: str, options: Options) -> ScanResult:
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError) as e:
        # A binary or non-UTF-8 file is unreadable input, reported as a finding like any other
        # unreadable file rather than as a traceback.
        return ScanResult(
            findings=[Finding(
                rule_id="RNV-000",
                severity=Severity.HIGH,
                message="cannot read file: " + str(e),
                pointer="<root>",
                path=path,
                hint="",
            )],
            files_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=str(e),
        )
    return scan_text(content, path, options)


def scan_paths(paths: Iterable[str], options: Options) -> ScanResult:
    merged = ScanResult()
    collected = []
    for p in paths:
        collected.append(p)
        targets = discover_paths(p)
        for t in targets:
            r = scan_file(t, options)
            merged.findings.extend(r.findings)
            merged.files_scanned += r.files_scanned
    merged.verdict = compute_verdict(
        merged.findings, merged.files_scanned, options
    )
    merged.findings.sort(key=lambda f: (f.path, f.pointer, f.rule_id))
    merged.source = ",".join(collected)
    return merged


__all__ = ["discover_paths", "scan_text", "scan_file", "scan_paths"]
