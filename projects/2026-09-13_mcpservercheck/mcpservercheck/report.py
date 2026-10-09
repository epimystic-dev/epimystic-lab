"""Text and JSON reporters for mcpservercheck scan results."""

import json
from typing import List

from .types import Finding, ScanResult, Severity
from .verdict import compute_verdict, counts, exit_code_for


def _visible_findings(result: ScanResult, include_info: bool) -> List[Finding]:
    if include_info:
        return list(result.findings)
    return [f for f in result.findings if f.severity != Severity.INFO]


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the paths and the server
      names, env keys and commands this tool echoes from an MCP config may
      contain exactly those characters. Echoing them raw crashed the
      reporter mid-write, so such inputs produced a traceback and no
      finding at all.
    * A hidden character must be made visible in the report, not echoed raw
      and so concealed a second time in the very output meant to expose it.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if 32 <= cp < 127:
            out.append(ch)
        else:
            out.append("<U+%04X>" % cp)
    return "".join(out)


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
    # Each line is one record; a newline inside a scanned path or a name
    # from the config is rendered as <U+000A> rather than forging a line.
    return "\n".join(_visible(line) for line in lines) + "\n"


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
