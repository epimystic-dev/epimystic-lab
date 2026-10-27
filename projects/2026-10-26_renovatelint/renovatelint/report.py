"""Text and JSON output formatting for renovatelint."""

from __future__ import annotations

import json
from typing import TextIO

from . import __version__
from .types import ScanResult, Severity


_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.INFO)


def _visible(text: str) -> str:
    """Render text so every character is printable ASCII.

    Any character outside printable ASCII is written as ``<U+XXXX>``.
    This keeps the reporter from crashing on a Windows cp1252 console
    when a scanned file carries bytes the console cannot encode (and
    keeps the rule output legible when the character is the finding
    itself, such as a Plane-14 TAG codepoint).
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if 32 <= cp < 127:
            out.append(ch)
        else:
            out.append("<U+%04X>" % cp)
    return "".join(out)


def write_text(result: ScanResult, stream: TextIO) -> None:
    if not result.findings:
        stream.write(
            "renovatelint: " + result.verdict.value
            + "; files=" + str(result.files_scanned)
            + " findings=0\n"
        )
        return
    by_sev = {s: [f for f in result.findings if f.severity is s]
              for s in _SEVERITY_ORDER}
    for sev in _SEVERITY_ORDER:
        for f in by_sev[sev]:
            stream.write(
                sev.value + " " + f.rule_id
                + " " + _visible(f.path) + " " + _visible(f.pointer)
                + ": " + _visible(f.message) + "\n"
            )
            if f.hint:
                stream.write("    hint: " + _visible(f.hint) + "\n")
    stream.write(
        "renovatelint: " + result.verdict.value
        + "; files=" + str(result.files_scanned)
        + " findings=" + str(len(result.findings)) + "\n"
    )


def write_json(result: ScanResult, stream: TextIO) -> None:
    """Emit the scan result as one JSON document on the given stream.

    Top-level shape follows docs/CONVENTIONS.md Structured output as the
    convergence target for severity-based linters: `tool`, `version`,
    and `source` identify the producer and the invocation, `findings`
    carries the per-rule hits, and `summary` carries the dict rollup
    (`total_findings`, `files_scanned`, `by_severity`) in the shape
    used by the other converged tools. The pre-0.2.0 keys (`verdict`,
    `files_scanned`, `findings`, `error`) are retained unchanged so
    existing consumers continue to work.
    """
    by_sev = {s.value: 0 for s in _SEVERITY_ORDER}
    for f in result.findings:
        by_sev[f.severity.value] += 1
    doc = {
        "tool": "renovatelint",
        "version": __version__,
        "source": result.source,
    }
    doc.update(result.to_dict())
    doc["summary"] = {
        "total_findings": len(result.findings),
        "files_scanned": result.files_scanned,
        "by_severity": by_sev,
    }
    json.dump(doc, stream, indent=2)
    stream.write("\n")


__all__ = ["write_text", "write_json"]
