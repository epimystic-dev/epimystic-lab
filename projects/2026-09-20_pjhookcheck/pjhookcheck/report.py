"""Text and JSON emitters.

Report writes findings to stdout and diagnostics (summary lines,
errors, verdict) to stderr, so `pjhookcheck --json ... | jq` is
safe. The text format is deterministic and stable.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, TextIO

from .types import Finding, Options, ScanResult, Severity, Verdict


def _sev_str(sev: Severity) -> str:
    return sev.value


def render_text(result: ScanResult, verdict: Verdict, options: Options,
                out: TextIO, err: TextIO) -> None:
    displayed: List[Finding] = [
        f for f in result.findings
        if not (f.severity is Severity.INFO and not options.include_info)
    ]
    for f in displayed:
        line = (
            f"{f.path}:{f.line}:{f.column}: "
            f"[{f.rule_id} {_sev_str(f.severity)}] {f.prop}: {f.message}"
        )
        out.write(line + "\n")
        if f.snippet:
            out.write(f"    | {f.snippet}\n")

    high = sum(1 for f in result.findings if f.severity is Severity.HIGH)
    medium = sum(1 for f in result.findings if f.severity is Severity.MEDIUM)
    info_visible = sum(
        1 for f in result.findings
        if f.severity is Severity.INFO and options.include_info
    )
    err.write(
        f"pjhookcheck: files={result.files_scanned} "
        f"high={high} medium={medium} info={info_visible} "
        f"errors={len(result.errors)}\n"
    )
    for e in result.errors:
        err.write(f"pjhookcheck: error: {e}\n")
    err.write(f"pjhookcheck: verdict={verdict.value}\n")


def render_json(result: ScanResult, verdict: Verdict, options: Options,
                out: TextIO, err: TextIO) -> None:
    doc: Dict[str, Any] = {
        "tool": "pjhookcheck",
        "verdict": verdict.value,
        "files_scanned": result.files_scanned,
        "findings": [
            {
                "rule": f.rule_id,
                "severity": _sev_str(f.severity),
                "path": f.path,
                "prop": f.prop,
                "line": f.line,
                "column": f.column,
                "message": f.message,
                "snippet": f.snippet,
            }
            for f in result.findings
            if not (f.severity is Severity.INFO and not options.include_info)
        ],
        "errors": list(result.errors),
    }
    out.write(json.dumps(doc, indent=2, sort_keys=True))
    out.write("\n")
    err.write(f"pjhookcheck: verdict={verdict.value}\n")
