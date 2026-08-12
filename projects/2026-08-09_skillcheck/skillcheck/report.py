"""Report formatting for skillcheck (JSON + text)."""

from __future__ import annotations

import json
from typing import List

from skillcheck.verdict import Finding, Report, Verdict, Severity


EXIT_SAFE = 0
EXIT_SUSPICIOUS = 1
EXIT_UNSAFE = 2
EXIT_UNKNOWN_DEFAULT = 1
EXIT_UNKNOWN_STRICT = 2


def build_report(verdict: Verdict, findings: List[Finding], files_scanned: List[str], errors: List[str]) -> Report:
    return Report(verdict=verdict, findings=list(findings), files_scanned=list(files_scanned), errors=list(errors))


def report_to_json(report: Report, *, include_info: bool = False) -> str:
    d = report.to_dict()
    if not include_info:
        d["findings"] = [f for f in d["findings"] if f["severity"] != Severity.INFO.value]
        # summary is authoritative regardless of include_info; keep as-is
    return json.dumps(d, sort_keys=True, indent=2)


def report_to_text(report: Report, *, include_info: bool = False) -> str:
    lines: List[str] = []
    lines.append(f"verdict: {report.verdict.value}")
    summary = report.summary()
    lines.append(
        "files_scanned={files_scanned} total_findings={total_findings} "
        "critical={c} high={h} medium={m} info={i}".format(
            files_scanned=summary["files_scanned"],
            total_findings=summary["total_findings"],
            c=summary["by_severity"]["critical"],
            h=summary["by_severity"]["high"],
            m=summary["by_severity"]["medium"],
            i=summary["by_severity"]["info"],
        )
    )
    if report.errors:
        lines.append("errors:")
        for e in report.errors:
            lines.append(f"  - {e}")
    lines.append("findings:")
    if not report.findings:
        lines.append("  (none)")
    else:
        for f in report.findings:
            if f.severity == Severity.INFO and not include_info:
                continue
            lines.append(
                f"  [{f.severity.value}] {f.rule_id} {f.file}:{f.line}:{f.column} -- {f.message}"
            )
            if f.excerpt:
                lines.append(f"      excerpt: {f.excerpt}")
    return "\n".join(lines)


def exit_code_for(report: Report, *, strict: bool = False) -> int:
    v = report.verdict
    if v == Verdict.SAFE:
        return EXIT_SAFE
    if v == Verdict.UNSAFE:
        return EXIT_UNSAFE
    if v == Verdict.SUSPICIOUS:
        return EXIT_SUSPICIOUS
    if v == Verdict.UNKNOWN:
        return EXIT_UNKNOWN_STRICT if strict else EXIT_UNKNOWN_DEFAULT
    return 1
