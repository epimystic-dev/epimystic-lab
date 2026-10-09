"""Text and JSON output formatting for mcptoolcheck."""

from __future__ import annotations

import json
from typing import TextIO

from .types import ScanResult, Severity


_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.INFO)


def _severity_label(sev: Severity) -> str:
    return sev.value


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the findings this tool
      exists to raise are made of exactly those characters. Echoing them raw
      crashed the reporter mid-write, so the most dangerous inputs produced a
      traceback and no finding at all.
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


def write_text(result: ScanResult, stream: TextIO) -> None:
    """Emit a human-readable report. Each finding occupies two lines
    (header + hint) so grep-based CI pipelines can anchor on the
    rule-id line.
    """
    if not result.findings:
        stream.write(
            "mcptoolcheck: " + result.verdict.value
            + "; files=" + str(result.files_scanned)
            + " tools=" + str(result.tools_scanned)
            + " findings=0\n"
        )
        return
    by_sev = {s: [f for f in result.findings if f.severity is s]
              for s in _SEVERITY_ORDER}
    for sev in _SEVERITY_ORDER:
        for f in by_sev[sev]:
            stream.write(
                _severity_label(sev) + " " + f.rule_id
                + " " + _visible(f.path) + " " + _visible(f.pointer)
                + " [" + _visible(f.tool_name) + "]: "
                + _visible(f.message) + "\n"
            )
            if f.hint:
                stream.write("    hint: " + _visible(f.hint) + "\n")
    stream.write(
        "mcptoolcheck: " + result.verdict.value
        + "; files=" + str(result.files_scanned)
        + " tools=" + str(result.tools_scanned)
        + " findings=" + str(len(result.findings)) + "\n"
    )


def write_json(result: ScanResult, stream: TextIO) -> None:
    json.dump(result.to_dict(), stream, indent=2)
    stream.write("\n")


__all__ = ["write_text", "write_json"]
