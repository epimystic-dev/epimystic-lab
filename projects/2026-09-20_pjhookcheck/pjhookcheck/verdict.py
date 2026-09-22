"""Verdict rollup and exit code."""

from __future__ import annotations

from typing import Iterable

from .types import Finding, Options, ScanResult, Severity, Verdict


def _filtered(findings: Iterable[Finding], include_info: bool) -> Iterable[Finding]:
    for f in findings:
        if f.severity is Severity.INFO and not include_info:
            continue
        yield f


def compute_verdict(result: ScanResult, options: Options) -> Verdict:
    """Roll findings up to one verdict.

    - unknown  when no files were scanned (and not --strict)
    - unhealthy on any HIGH, on any INFO under --strict, or on
      any error
    - needs-attention on any MEDIUM (or on INFO under --include-info
      that has not already been escalated)
    - healthy otherwise
    """
    if result.errors:
        return Verdict.UNHEALTHY
    if result.files_scanned == 0:
        return Verdict.UNHEALTHY if options.strict else Verdict.UNKNOWN

    has_high = False
    has_medium = False
    has_info = False
    for f in result.findings:
        if f.severity is Severity.HIGH:
            has_high = True
        elif f.severity is Severity.MEDIUM:
            has_medium = True
        elif f.severity is Severity.INFO:
            has_info = True

    if has_high:
        return Verdict.UNHEALTHY
    if options.strict and has_info:
        return Verdict.UNHEALTHY
    if has_medium:
        return Verdict.NEEDS_ATTENTION
    if options.include_info and has_info:
        return Verdict.NEEDS_ATTENTION
    return Verdict.HEALTHY


def exit_code(verdict: Verdict) -> int:
    return {
        Verdict.HEALTHY: 0,
        Verdict.NEEDS_ATTENTION: 1,
        Verdict.UNHEALTHY: 2,
        Verdict.UNKNOWN: 0,
    }[verdict]
