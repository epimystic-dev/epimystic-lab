"""Reporters for nbshape.

Stream discipline, per epimystic-lab/docs/CONVENTIONS.md:

  stdout   findings, one per line, or the whole JSON document under --json
  stderr   the verdict line, counts, per-file diagnostics - every label and
           every piece of human chatter

A clean run therefore writes nothing at all to stdout, so a caller piping
stdout into jq or into a diff never sees the tool's own commentary.
"""

from __future__ import annotations

import json
from typing import List

from .rules import ALWAYS_VISIBLE_IDS
from .types import Finding, ScanResult, Severity
from .verdict import compute_verdict, counts, exit_code_for


def visible_findings(result: ScanResult, include_info: bool) -> List[Finding]:
    """Findings the user asked to see.

    INFO findings are hidden unless --include-info, with one exception: a rule
    marked always-visible (the NBK-010 conformance gate) stays on screen,
    because hiding the reason a file could not be scored would be dishonest.
    """
    if include_info:
        return list(result.findings)
    return [
        f
        for f in result.findings
        if f.severity != Severity.INFO or f.rule_id in ALWAYS_VISIBLE_IDS
    ]


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the notebook paths, path
      literals, and cell ids this tool echoes can carry exactly those
      characters. Echoing them raw crashed the reporter mid-write, so the
      input produced a traceback and no finding at all.
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


def format_findings(result: ScanResult, include_info: bool = False) -> str:
    """Findings only, for stdout. Empty string when there is nothing to show."""
    lines = []
    for f in visible_findings(result, include_info):
        cell = "notebook" if f.cell < 0 else "cell " + str(f.cell)
        lines.append(
            f.severity.value + " " + f.rule_id + " " + f.path + ":" + str(f.line) +
            ":" + str(f.column) + " [" + cell + "] " + f.message
        )
    if not lines:
        return ""
    # Each line is one record; a newline inside a path or an echoed fragment
    # is rendered as <U+000A> rather than starting a forged line of its own.
    return "\n".join(_visible(line) for line in lines) + "\n"


def format_summary(result: ScanResult, strict: bool = False, include_info: bool = False) -> str:
    """Verdict, counts, and per-file diagnostics, for stderr."""
    verdict = compute_verdict(result, strict=strict)
    high, medium, info = counts(result)
    visible = visible_findings(result, include_info)
    lines = [
        "verdict: " + verdict.value,
        (
            "files_scanned=" + str(result.files_scanned) +
            " files_scored=" + str(result.files_scored) +
            " files_unknown=" + str(result.files_unknown)
        ),
        (
            "findings_total=" + str(len(result.findings)) +
            " high=" + str(high) +
            " medium=" + str(medium) +
            " info=" + str(info) +
            " visible=" + str(len(visible)) +
            " hidden=" + str(len(result.findings) - len(visible))
        ),
    ]
    for e in result.errors:
        lines.append("diagnostic: " + e)
    return "\n".join(_visible(line) for line in lines) + "\n"


def format_json(result: ScanResult, strict: bool = False, include_info: bool = False) -> str:
    """The whole report as one deterministic JSON document, for stdout."""
    verdict = compute_verdict(result, strict=strict)
    high, medium, info = counts(result)
    visible = visible_findings(result, include_info)
    payload = {
        "tool": "nbshape",
        "verdict": verdict.value,
        "exit_code": exit_code_for(verdict, strict=strict),
        "files_scanned": result.files_scanned,
        "files_scored": result.files_scored,
        "files_unknown": result.files_unknown,
        "counts": {
            "high": high,
            "medium": medium,
            "info": info,
            "total": len(result.findings),
            "visible": len(visible),
        },
        "findings": [f.to_dict() for f in visible],
        "errors": list(result.errors),
    }
    return json.dumps(payload, sort_keys=True, indent=2) + "\n"
