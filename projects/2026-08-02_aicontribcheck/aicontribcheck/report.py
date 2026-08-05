"""Output formatters (human text + JSON)."""

from __future__ import annotations

import json

from .types import RepoReport, Severity, Verdict


_ORDER = {
    Severity.ERROR: 0,
    Severity.WARN: 1,
    Severity.INFO: 2,
}


def format_json(report: RepoReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


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
    return "\n".join(lines)


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
