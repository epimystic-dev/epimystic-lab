"""Verdict rollup. Severity -> verdict -> exit code mapping follows
Convention B from the lab's CONVENTIONS.md.
"""

from __future__ import annotations

from typing import List

from .types import Finding, Options, Severity, Verdict


def compute_verdict(
    findings: List[Finding], files_scanned: int, options: Options
) -> Verdict:
    highs = [f for f in findings if f.severity is Severity.HIGH]
    if highs:
        return Verdict.UNHEALTHY
    if files_scanned == 0:
        return Verdict.UNKNOWN
    meds = [f for f in findings if f.severity is Severity.MEDIUM]
    if meds:
        return Verdict.NEEDS_ATTENTION
    infos = [f for f in findings if f.severity is Severity.INFO]
    if infos and options.strict:
        return Verdict.NEEDS_ATTENTION
    return Verdict.HEALTHY


def exit_code(verdict: Verdict, options: Options) -> int:
    if verdict is Verdict.HEALTHY:
        return 0
    if verdict is Verdict.NEEDS_ATTENTION:
        return 1
    if verdict is Verdict.UNHEALTHY:
        return 2
    return 2 if options.strict else 1


__all__ = ["compute_verdict", "exit_code"]
