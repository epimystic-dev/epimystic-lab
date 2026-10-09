"""Human-readable and JSON reporters for licensechain findings."""

from __future__ import annotations
import json
from typing import List, Iterable

from .rules import Finding, Severity


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the manifest path and the
      component names this tool echoes can contain exactly those
      characters. Echoing them raw crashed the reporter mid-write, so the
      manifest produced a traceback and no finding at all.
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


def format_text(findings: List[Finding], source_label: str = "") -> str:
    """Human-readable report suitable for CLI output.

    A single line per finding, plus a trailing summary line. Deterministic.
    """
    lines: List[str] = []
    if source_label:
        lines.append(f"# licensechain report for {source_label}")

    if not findings:
        lines.append("no findings.")
        return "\n".join(_visible(line) for line in lines) + "\n"

    for f in findings:
        prefix = f"[{f.severity.value.upper():5s}] {f.rule}"
        subject = f.component
        if f.upstream:
            subject = f"{f.component} <- {f.upstream}"
        lines.append(f"{prefix}  {subject}: {f.message}")

    err = sum(1 for f in findings if f.severity == Severity.ERROR)
    warn = sum(1 for f in findings if f.severity == Severity.WARN)
    info = sum(1 for f in findings if f.severity == Severity.INFO)
    lines.append(
        f"summary: {err} error(s), {warn} warning(s), {info} info"
    )
    # Each line is one record; a newline inside a path or component name is
    # rendered as <U+000A> rather than starting a forged line of its own.
    return "\n".join(_visible(line) for line in lines) + "\n"


def format_json(findings: List[Finding], source_label: str = "") -> str:
    """Machine-readable JSON report."""
    err = sum(1 for f in findings if f.severity == Severity.ERROR)
    warn = sum(1 for f in findings if f.severity == Severity.WARN)
    info = sum(1 for f in findings if f.severity == Severity.INFO)
    payload = {
        "source": source_label,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "error": err,
            "warn": warn,
            "info": info,
            "total": len(findings),
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def compute_exit_code(findings: Iterable[Finding], strict: bool = False
                      ) -> int:
    """Map findings to a shell exit code:
        0 -- no findings above INFO (or no findings at all).
        1 -- warnings but no errors.
        2 -- at least one error.
    With strict=True, warnings are promoted to errors.
    """
    has_error = any(f.severity == Severity.ERROR for f in findings)
    has_warn = any(f.severity == Severity.WARN for f in findings)
    if strict and has_warn:
        return 2
    if has_error:
        return 2
    if has_warn:
        return 1
    return 0
