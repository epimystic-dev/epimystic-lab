"""Report shaping + rendering (JSON + text)."""

from __future__ import annotations

import json
from typing import Iterable, List

from oraclecheck.types import Finding, ScanResult, Severity, Verdict
from oraclecheck.verdict import rollup_verdict


def build_report(results: List[ScanResult], strict: bool, include_info: bool) -> dict:
    files_scanned = sum(1 for r in results if r.error is None)
    all_findings: List[Finding] = []
    for r in results:
        all_findings.extend(r.findings)
    visible = [f for f in all_findings if include_info or f.severity != Severity.INFO]
    verdict, exit_code = rollup_verdict(files_scanned, all_findings, strict)
    return {
        "verdict": verdict.value,
        "exit_code": exit_code,
        "files_scanned": files_scanned,
        "files_errored": sum(1 for r in results if r.error is not None),
        "findings_total": len(all_findings),
        "findings_visible": len(visible),
        "findings": [f.to_json_dict() for f in sorted(visible, key=lambda f: f.sort_key())],
        "errors": [
            {"path": r.path, "error": r.error}
            for r in results
            if r.error is not None
        ],
    }


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=True)


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the paths, identifiers and
      error lines this tool prints may contain exactly those characters.
      Echoing them raw crashed the reporter mid-write, so such inputs
      produced a traceback and no finding at all.
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


def render_text(report: dict) -> str:
    lines: List[str] = []
    for f in report["findings"]:
        lines.append(f"{f['path']}:{f['line']}:{f['column']}: {f['severity']} {f['rule_id']} {f['message']}")
    for e in report["errors"]:
        lines.append(f"{e['path']}: ERROR {e['error']}")
    lines.append(
        f"verdict: {report['verdict']} (files_scanned={report['files_scanned']}, "
        f"findings={report['findings_total']} visible={report['findings_visible']}, "
        f"exit={report['exit_code']})"
    )
    # Each line is one record; a newline inside a scanned path or message is
    # rendered as <U+000A> rather than starting a forged line of its own.
    return "\n".join(_visible(line) for line in lines) + "\n"
