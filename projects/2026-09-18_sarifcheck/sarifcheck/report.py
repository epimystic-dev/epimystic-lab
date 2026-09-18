"""Text and JSON reporters for sarifcheck.

Stream discipline, per the shared lab CLI contract: findings and structured
output go to STDOUT, every human label / summary / diagnostic goes to
STDERR. A caller piping stdout into a JSON parser never sees chatter.

Redaction discipline: `snippet` holds the matched text for the path-shape
and token-shape rules. It is omitted from both renderers unless
--show-matches is given, because a linter whose own output reprints a host
path into a CI log has republished the thing it is complaining about.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence

from .types import Finding, ScanResult, Severity
from .verdict import compute_verdict, counts, exit_code_for


DISCLAIMER = (
    "sarifcheck checks a named subset of SARIF 2.1.0 property paths plus "
    "documented ingest ceilings. It is not a JSON Schema validator, and a "
    "clean run is not a promise that any endpoint will accept the file."
)


def visible_findings(result: ScanResult, include_info: bool) -> List[Finding]:
    if include_info:
        return list(result.findings)
    return [f for f in result.findings if f.severity != Severity.INFO]


def format_findings_text(
    result: ScanResult,
    include_info: bool = False,
    show_matches: bool = False,
) -> str:
    """Findings only, one per line. STDOUT."""
    lines: List[str] = []
    for finding in visible_findings(result, include_info):
        line = (
            finding.severity.value + " " + finding.rule_id + " " + finding.path
            + ":" + str(finding.line) + ":" + str(finding.column) + " "
            + finding.prop + " " + finding.message
        )
        if show_matches and finding.snippet:
            line += "  match=" + repr(finding.snippet)
        lines.append(line)
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def format_summary_text(
    result: ScanResult,
    strict: bool = False,
    include_info: bool = False,
    profiles: Optional[Sequence[str]] = None,
) -> str:
    """Labels, counts, verdict, errors and notes. STDERR."""
    verdict = compute_verdict(result, strict=strict)
    high, medium, info = counts(result)
    visible = visible_findings(result, include_info)
    lines = [
        DISCLAIMER,
        "verdict: " + verdict.value,
        (
            "files_scanned=" + str(result.files_scanned)
            + " findings_total=" + str(len(result.findings))
            + " high=" + str(high)
            + " medium=" + str(medium)
            + " info=" + str(info)
        ),
        (
            "findings_visible=" + str(len(visible))
            + " findings_hidden=" + str(len(result.findings) - len(visible))
        ),
    ]
    if profiles:
        lines.append("profiles: " + ",".join(sorted(profiles)))
    if result.partial:
        lines.append(
            "partial: at least one run references external property files that "
            "were not read; the verdict cannot be 'healthy'"
        )
    for note in result.notes:
        lines.append("NOTE " + note)
    for error in result.errors:
        lines.append("ERROR " + error)
    return "\n".join(lines) + "\n"


def finding_to_dict(finding: Finding, show_matches: bool = False) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "path": finding.path,
        "property": finding.prop,
        "line": finding.line,
        "column": finding.column,
        "message": finding.message,
        "run_index": finding.run_index,
        "result_index": finding.result_index,
    }
    if show_matches:
        payload["match"] = finding.snippet
    return payload


def format_json(
    result: ScanResult,
    tool: str,
    version: str,
    strict: bool = False,
    include_info: bool = False,
    show_matches: bool = False,
    profiles: Optional[Sequence[str]] = None,
    limits: Optional[Dict[str, int]] = None,
) -> str:
    """Deterministic structured output. STDOUT.

    Keys are sorted and findings are already ordered by
    (file, run index, result index, rule code, property path), so two runs
    over the same input produce byte-identical output and two commits can be
    diffed directly.
    """
    verdict = compute_verdict(result, strict=strict)
    high, medium, info = counts(result)
    visible = visible_findings(result, include_info)
    payload = {
        "tool": tool,
        "version": version,
        "disclaimer": DISCLAIMER,
        "verdict": verdict.value,
        "exit_code": exit_code_for(
            verdict, strict=strict, hard_error=bool(result.errors)
        ),
        "files_scanned": result.files_scanned,
        "partial": result.partial,
        "profiles": sorted(profiles) if profiles else [],
        "limits": dict(limits or {}),
        "counts": {
            "high": high,
            "medium": medium,
            "info": info,
            "total": len(result.findings),
            "visible": len(visible),
            "hidden": len(result.findings) - len(visible),
        },
        "findings": [finding_to_dict(f, show_matches=show_matches) for f in visible],
        "errors": list(result.errors),
        "notes": list(result.notes),
    }
    return json.dumps(payload, sort_keys=True, indent=2) + "\n"
