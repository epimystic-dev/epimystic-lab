"""Report formatters: text and JSON."""

import json
from typing import Any, Dict

from .config import Config
from .types import Finding, ScanReport, Severity, Verdict
from .verdict import compute_verdict


def _finding_dict(f: Finding) -> Dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "message": f.message,
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "detail": f.detail,
    }


def format_json(report: ScanReport, cfg: Config, strict: bool = False, include_info: bool = True) -> str:
    verdict, exit_code = compute_verdict(report, cfg, strict=strict)
    findings = report.all_findings()
    if not include_info:
        findings = [f for f in findings if f.severity != Severity.INFO]
    payload = {
        "tool": "agentmdlint",
        "version": _tool_version(),
        "root": report.root,
        "verdict": verdict.value,
        "exit_code": exit_code,
        "summary": {
            "files_scanned": report.files_scanned(),
            "files_seen": len(report.file_reports),
            "findings_total": len(findings),
            "findings_by_severity": _by_severity(findings),
        },
        "files": [
            {
                "path": fr.path,
                "bytes_read": fr.bytes_read,
                "read_error": fr.read_error,
                "findings_total": sum(
                    1 for f in fr.findings if include_info or f.severity != Severity.INFO
                ),
            }
            for fr in report.file_reports
        ],
        "findings": [_finding_dict(f) for f in findings],
    }
    return json.dumps(payload, sort_keys=True, indent=2)


def _by_severity(findings) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the paths and heading text
      this tool echoes can contain exactly those characters. Echoing them
      raw crashed the reporter mid-write, so the scan produced a traceback
      and no finding at all.
    * A concealed character must be made visible in the report, not echoed
      raw and so concealed a second time in the very output meant to expose
      it.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if 32 <= cp < 127:
            out.append(ch)
        else:
            out.append("<U+%04X>" % cp)
    return "".join(out)


def format_text(report: ScanReport, cfg: Config, strict: bool = False, include_info: bool = False) -> str:
    verdict, exit_code = compute_verdict(report, cfg, strict=strict)
    findings = report.all_findings()
    if not include_info:
        findings = [f for f in findings if f.severity != Severity.INFO]

    lines = []
    lines.append("agentmdlint " + _tool_version())
    lines.append("root: " + report.root)
    lines.append(
        "files: " + str(report.files_scanned())
        + " scanned / " + str(len(report.file_reports)) + " seen"
    )
    lines.append("verdict: " + verdict.value + " (exit " + str(exit_code) + ")")

    if not findings:
        if verdict == Verdict.HEALTHY:
            lines.append("no findings")
        elif verdict == Verdict.UNKNOWN:
            lines.append("no instruction files found")
        else:
            lines.append("no findings above the display threshold")
        return "\n".join(_visible(line) for line in lines) + "\n"

    lines.append("")
    lines.append("findings (" + str(len(findings)) + "):")
    for f in findings:
        loc = "L" + str(f.line) if f.line else "-"
        if f.column:
            loc += ":C" + str(f.column)
        lines.append(
            "  [" + f.severity.value.upper() + "] " + f.rule_id
            + " " + f.path + " " + loc + " " + f.message
        )
    # Each line is one record; a newline inside a path or heading is
    # rendered as <U+000A> rather than starting a forged line of its own.
    return "\n".join(_visible(line) for line in lines) + "\n"


def _tool_version() -> str:
    from . import __version__
    return __version__
