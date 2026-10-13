"""Scanner: open file(s), parse, run rules, roll up verdict."""

from __future__ import annotations

import os
from typing import Iterable

from .parse import load_text
from .rules import run_all
from .types import Finding, Options, ScanResult, Severity, Verdict
from .verdict import compute_verdict


_EXTENSIONS = (".json", ".jsonl", ".ndjson")


def scan_text(
    content: str, path: str, options: Options
) -> ScanResult:
    """Scan one memory-store string. ``path`` is the display label."""
    doc, store_meta, entries, err = load_text(content, path)
    if err is not None:
        return ScanResult(
            findings=[Finding(
                rule_id="AMC-000",
                severity=Severity.HIGH,
                message=err,
                entry_id="",
                pointer="<root>",
                path=path,
                hint="file is not valid JSON or JSONL",
            )],
            files_scanned=1,
            entries_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=err,
        )
    findings = run_all(doc, store_meta, content, path, options, entries)
    r = ScanResult(
        findings=findings,
        files_scanned=1,
        entries_scanned=len(entries),
    )
    r.verdict = compute_verdict(findings, r.files_scanned, options)
    return r


def scan_file(path: str, options: Options) -> ScanResult:
    """Scan one file. Returns a ScanResult; IO errors become a single
    HIGH finding so the verdict rollup stays uniform.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        return ScanResult(
            findings=[Finding(
                rule_id="AMC-000",
                severity=Severity.HIGH,
                message="cannot read file: " + str(e),
                entry_id="",
                pointer="<root>",
                path=path,
                hint="",
            )],
            files_scanned=0,
            entries_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=str(e),
        )
    return scan_text(content, path, options)


def scan_paths(
    paths: Iterable[str], options: Options
) -> ScanResult:
    """Scan every path, merging into one ScanResult."""
    merged = ScanResult()
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in files:
                    if name.endswith(_EXTENSIONS):
                        r = scan_file(os.path.join(root, name), options)
                        merged.findings.extend(r.findings)
                        merged.files_scanned += r.files_scanned
                        merged.entries_scanned += r.entries_scanned
        else:
            r = scan_file(p, options)
            merged.findings.extend(r.findings)
            merged.files_scanned += r.files_scanned
            merged.entries_scanned += r.entries_scanned
    merged.verdict = compute_verdict(
        merged.findings, merged.files_scanned, options
    )
    merged.findings.sort(key=lambda f: (f.path, f.pointer, f.rule_id))
    return merged


__all__ = ["scan_text", "scan_file", "scan_paths"]
