"""Verdict rollup.

- any HIGH  -> unhealthy (exit 2)
- any MEDIUM without HIGH -> needs-attention (exit 1)
- INFO-only + files scanned -> healthy default (exit 0); strict -> needs-attention (exit 1)
- no findings + files scanned -> healthy (exit 0)
- no files scanned -> unknown (exit 1 default, exit 2 strict)
"""

from __future__ import annotations

from typing import Iterable, Tuple

from oraclecheck.types import Finding, Severity, Verdict


def rollup_verdict(
    files_scanned: int,
    findings: Iterable[Finding],
    strict: bool,
) -> Tuple[Verdict, int]:
    findings = list(findings)
    if files_scanned == 0:
        return Verdict.UNKNOWN, (2 if strict else 1)
    highs = any(f.severity == Severity.HIGH for f in findings)
    mediums = any(f.severity == Severity.MEDIUM for f in findings)
    infos = any(f.severity == Severity.INFO for f in findings)
    if highs:
        return Verdict.UNHEALTHY, 2
    if mediums:
        return Verdict.NEEDS_ATTENTION, 1
    if infos and strict:
        return Verdict.NEEDS_ATTENTION, 1
    return Verdict.HEALTHY, 0
