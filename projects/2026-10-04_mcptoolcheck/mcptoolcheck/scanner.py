"""Scanner: open file(s), parse, run rules, roll up verdict."""

from __future__ import annotations

import os
from typing import Iterable, List

from .parse import extract_tools, load_json
from .rules import run_all
from .types import Finding, Options, ScanResult, Severity, Verdict
from .verdict import compute_verdict


def scan_text(
    content: str, path: str, options: Options
) -> ScanResult:
    """Scan one JSON string. ``path`` is the display label."""
    doc, err = load_json(content)
    if err is not None:
        return ScanResult(
            findings=[Finding(
                rule_id="MTC-000",
                severity=Severity.HIGH,
                message=err,
                tool_name="",
                pointer="<root>",
                path=path,
                hint="file is not valid JSON",
            )],
            files_scanned=1,
            tools_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=err,
        )
    tools = extract_tools(doc)
    findings = run_all(doc, content, path, options, tools)
    r = ScanResult(
        findings=findings,
        files_scanned=1,
        tools_scanned=len(tools),
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
                rule_id="MTC-000",
                severity=Severity.HIGH,
                message="cannot read file: " + str(e),
                tool_name="",
                pointer="<root>",
                path=path,
                hint="",
            )],
            files_scanned=0,
            tools_scanned=0,
            verdict=Verdict.UNHEALTHY,
            error=str(e),
        )
    return scan_text(content, path, options)


def scan_paths(
    paths: Iterable[str], options: Options
) -> ScanResult:
    """Scan every path, merging into one ScanResult."""
    merged = ScanResult()
    seen = 0
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in files:
                    if name.endswith(".json"):
                        r = scan_file(os.path.join(root, name), options)
                        merged.findings.extend(r.findings)
                        merged.files_scanned += r.files_scanned
                        merged.tools_scanned += r.tools_scanned
                        seen += r.files_scanned
        else:
            r = scan_file(p, options)
            merged.findings.extend(r.findings)
            merged.files_scanned += r.files_scanned
            merged.tools_scanned += r.tools_scanned
            seen += r.files_scanned
    merged.verdict = compute_verdict(
        merged.findings, merged.files_scanned, options
    )
    merged.findings.sort(key=lambda f: (f.path, f.pointer, f.rule_id))
    return merged


__all__ = ["scan_text", "scan_file", "scan_paths"]
