"""Output formatters (human text + JSON)."""

from __future__ import annotations

import json

from . import __version__
from .types import RepoReport, Severity, Verdict


_ORDER = {
    Severity.ERROR: 0,
    Severity.WARN: 1,
    Severity.INFO: 2,
}


def format_json(report: RepoReport) -> str:
    """Machine-readable JSON report.

    Top-level shape follows docs/CONVENTIONS.md as the convergence target
    for severity-based linters: ``tool`` and ``version`` identify the
    producer so a log aggregator receiving JSON from several lab tools can
    tell them apart without out-of-band knowledge; ``source`` carries the
    repository root the findings were derived from; ``findings`` is a flat
    list of every finding across every scanned file (previously only
    reachable by walking ``files[].findings``); and ``summary`` is
    unchanged from the pre-0.3.0 shape. All pre-0.3.0 keys (``root``,
    ``verdict``, ``files``, ``required_disclosures``,
    ``required_attributions``, ``tools_named``, ``summary``) are retained
    so existing consumers continue to work.
    """
    payload = report.to_dict()
    payload["tool"] = "aicontribcheck"
    payload["version"] = __version__
    payload["source"] = report.root
    payload["findings"] = [f.to_dict() for f in report.all_findings()]
    return json.dumps(payload, indent=2, sort_keys=True)


def _visible(text: str) -> str:
    """Render text so that every character is printable ASCII.

    Any character outside printable ASCII is written as <U+XXXX>. There are
    two reasons, and both matter for this tool in particular:

    * A report must never crash on a console that cannot encode what it is
      reporting. A Windows console using code page 1252 cannot encode a
      zero-width space or a Cyrillic letter, and the evidence lines this
      tool quotes from policy files (and the paths it echoes) can contain
      exactly those characters. Echoing them raw crashed the reporter
      mid-write, so the scan produced a traceback and no finding at all.
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


def format_text(report: RepoReport) -> str:
    lines = []
    lines.append(f"aicontribcheck :: {report.root}")
    lines.append(f"  verdict         : {report.verdict.value}")
    lines.append(f"  files scanned   : {len(report.files_scanned)}")
    lines.append(f"  tools named     : {', '.join(report.tools_named) or '-'}")
    lines.append(
        f"  disclosures req : "
        + ("; ".join(report.required_disclosures) or "-")
    )
    lines.append(
        f"  attributions req: "
        + ("; ".join(report.required_attributions) or "-")
    )
    lines.append("")
    findings = report.all_findings()
    findings_sorted = sorted(
        findings,
        key=lambda f: (_ORDER[f.severity], f.file, f.line, f.rule),
    )
    if not findings_sorted:
        lines.append("  (no findings)")
    else:
        lines.append("findings:")
        for f in findings_sorted:
            lines.append(
                f"  [{f.severity.value.upper():5}] "
                f"{f.rule} {f.file}:{f.line} -- {f.message}"
            )
            if f.evidence:
                lines.append(f"          evidence: {f.evidence}")
    # Each line is one record; a newline inside a path or quoted evidence is
    # rendered as <U+000A> rather than starting a forged line of its own.
    return "\n".join(_visible(line) for line in lines)


def exit_code(report: RepoReport, strict: bool = False) -> int:
    """Return the process exit code for a report.

    Mapping (default):
      allowed     => 0
      conditional => 1
      unknown     => 1
      banned      => 2
      conflict    => 2

    With --strict, unknown becomes 2.
    """
    v = report.verdict
    if v is Verdict.ALLOWED:
        return 0
    if v is Verdict.BANNED or v is Verdict.CONFLICT:
        return 2
    if v is Verdict.UNKNOWN and strict:
        return 2
    return 1
