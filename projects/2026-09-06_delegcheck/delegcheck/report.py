"""Text and JSON reporters for delegcheck scan results."""

import json
from typing import Iterable, List

from .types import Finding, ScanResult, Severity, Verdict
from .verdict import compute_verdict, counts, exit_code_for


def _visible_findings(result: ScanResult, include_info: bool) -> List[Finding]:
    if include_info:
        return list(result.findings)
    return [f for f in result.findings if f.severity != Severity.INFO]


def format_text(result: ScanResult, strict: bool = False, include_info: bool = False) -> str:
    verdict = compute_verdict(result, strict=strict)
    high, medium, info = counts(result)
    visible = _visible_findings(result, include_info)
    lines = [
        "verdict: " + verdict.value,
        (
            "files_scanned=" + str(result.files_scanned) +
            " findings_total=" + str(len(result.findings)) +
            " high=" + str(high) +
            " medium=" + str(medium) +
            " info=" + str(info)
        ),
        (
            "findings_visible=" + str(len(visible)) +
            " findings_hidden=" + str(len(result.findings) - len(visible))
        ),
    ]
    for f in visible:
        lines.append(
            "  " + f.severity.value + " " + f.rule_id + " " +
            f.path + ":" + str(f.line) + ":" + str(f.column) + " " + f.message
        )
    for e in result.errors:
        lines.append("  ERROR " + e)
    return "\n".join(lines) + "\n"


def format_json(result: ScanResult, strict: bool = False, include_info: bool = False) -> str:
    verdict = compute_verdict(result, strict=strict)
    high, medium, info = counts(result)
    visible = _visible_findings(result, include_info)
    payload = {
        "verdict": verdict.value,
        "exit_code": exit_code_for(verdict, strict=strict),
        "files_scanned": result.files_scanned,
        "counts": {
            "high": high,
            "medium": medium,
            "info": info,
            "total": len(result.findings),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "message": f.message,
                "snippet": f.snippet,
            }
            for f in visible
        ],
        "errors": list(result.errors),
    }
    return json.dumps(payload, sort_keys=True, indent=2) + "\n"
