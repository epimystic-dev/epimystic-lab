"""Verdict rollup. Severity -> verdict -> exit code mapping follows
Convention B from the lab's CONVENTIONS.md and the pattern used by
mcpservercheck / delegcheck / approvchainlint.

Rules:
  - any HIGH finding                           -> UNHEALTHY       (rc 2)
  - any MEDIUM finding, no HIGH                -> NEEDS_ATTENTION (rc 1)
  - only INFO findings, no HIGH or MEDIUM      -> NEEDS_ATTENTION (rc 1)
                                                   if options.strict,
                                                   else HEALTHY   (rc 0)
  - no findings at all, files scanned          -> HEALTHY         (rc 0)
  - no files scanned                           -> UNKNOWN         (rc 1
                                                   default, rc 2
                                                   if --strict)
"""

from __future__ import annotations

from typing import List

from .types import Finding, Options, Severity, Verdict


def compute_verdict(
    findings: List[Finding], files_scanned: int, options: Options
) -> Verdict:
    # Any HIGH finding dominates the rollup - even when files_scanned
    # is 0 (as happens on an OSError at open time, where the IO error
    # is surfaced as a HIGH MTC-000 finding).
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
