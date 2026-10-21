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

from . import __version__
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
    """The whole report as one deterministic JSON document, for stdout.

    Top-level shape follows docs/CONVENTIONS.md as the convergence target
    for severity-based linters: `tool` and `version` identify the producer
    so a log aggregator receiving JSON from several lab tools can tell
    them apart without out-of-band knowledge; `source` carries the scanned
    path the findings were derived from; `summary` carries the dict rollup
    (`total_findings`, `files_scanned`, `by_severity`) in the shape used
    by the other converged tools. Pre-0.3.0 keys (`verdict`, `exit_code`,
    `files_scanned`, `files_scored`, `files_unknown`, `counts`, `findings`,
    `errors`) are retained unchanged so existing consumers continue to
    work. Added 2026-10-21 as the eighth additive-only case in the
    campaign (after licensechain 2026-10-10, aicontribcheck 2026-10-13,
    skillcheck 2026-10-14, delegcheck 2026-10-15, oraclecheck 2026-10-16,
    elevatescan 2026-10-17, mcpservercheck 2026-10-20). `summary` is
    authoritative over the full finding set regardless of `include_info`,
    matching the convention used by the predecessor converged tools: a
    CI consumer checking `summary.total_findings` sees the ground truth
    of what the tool found, not what the current filter chose to echo
    on the wire.
    """
    verdict = compute_verdict(result, strict=strict)
    high, medium, info = counts(result)
    visible = visible_findings(result, include_info)
    payload = {
        "tool": "nbshape",
        "version": __version__,
        "source": result.source,
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
        "summary": {
            "total_findings": len(result.findings),
            "files_scanned": result.files_scanned,
            "by_severity": {
                "HIGH": high,
                "MEDIUM": medium,
                "INFO": info,
            },
        },
        "findings": [f.to_dict() for f in visible],
        "errors": list(result.errors),
    }
    return json.dumps(payload, sort_keys=True, indent=2) + "\n"
