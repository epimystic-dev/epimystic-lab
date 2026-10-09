from __future__ import annotations

import json
from typing import List

from .config import Config
from .types import Finding, ScanResult, Severity, Verdict


def _visible(findings: List[Finding], config: Config) -> List[Finding]:
    if config.include_info:
        return findings
    return [f for f in findings if f.severity != Severity.INFO]


def _printable(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. (The name
    _visible is taken in this module by the INFO-severity filter above.)
    There are two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the paths and error lines
      this tool prints may contain exactly those characters. Echoing them
      raw crashed the reporter mid-write, so such inputs produced a
      traceback and no finding at all.
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


def render_text(result: ScanResult, verdict: Verdict, config: Config) -> str:
    lines: List[str] = []
    visible = _visible(result.findings, config)
    counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for f in result.findings:
        counts[f.severity.value] += 1
    lines.append(f"verdict: {verdict.value}")
    lines.append(
        "files_scanned={fs} findings_total={tot} high={h} medium={m} info={i}".format(
            fs=result.files_scanned,
            tot=len(result.findings),
            h=counts["HIGH"],
            m=counts["MEDIUM"],
            i=counts["INFO"],
        )
    )
    lines.append(f"findings_visible={len(visible)} findings_hidden={len(result.findings) - len(visible)}")
    if result.errors:
        lines.append(f"errors: {len(result.errors)}")
        for path, msg in result.errors:
            lines.append(f"  ERR {path}: {msg}")
    for f in visible:
        lines.append(
            "  {sev} {rule} {path}:{line}:{col} {msg}".format(
                sev=f.severity.value,
                rule=f.rule_id,
                path=f.path,
                line=f.line,
                col=f.column,
                msg=f.message,
            )
        )
    # Each line is one record; a newline inside a scanned path or error
    # message is rendered as <U+000A> rather than starting a forged line.
    return "\n".join(_printable(line) for line in lines) + "\n"


def render_json(result: ScanResult, verdict: Verdict, config: Config) -> str:
    counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for f in result.findings:
        counts[f.severity.value] += 1
    visible = _visible(result.findings, config)
    obj = {
        "verdict": verdict.value,
        "files_scanned": result.files_scanned,
        "findings_total": len(result.findings),
        "findings_visible": len(visible),
        "counts": counts,
        "errors": [{"path": p, "message": m} for p, m in result.errors],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in visible
        ],
    }
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"
