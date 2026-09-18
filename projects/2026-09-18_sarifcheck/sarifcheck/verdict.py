"""Verdict rollup and exit-code mapping."""

from __future__ import annotations

from typing import Tuple

from .types import ScanResult, Severity, Verdict


def compute_verdict(result: ScanResult, strict: bool = False) -> Verdict:
    """Roll up findings into a single verdict.

    - No files scanned            -> UNKNOWN
    - A hard read / parse error   -> UNKNOWN
    - Any HIGH                    -> UNHEALTHY
    - Any MEDIUM (no HIGH)        -> NEEDS_ATTENTION
    - Partial analysis, no HIGH / MEDIUM -> UNKNOWN
    - Only INFO                   -> HEALTHY (default), NEEDS_ATTENTION (strict)
    - No findings, files scanned  -> HEALTHY
    """
    if result.files_scanned <= 0:
        return Verdict.UNKNOWN
    has_high = any(f.severity == Severity.HIGH for f in result.findings)
    has_medium = any(f.severity == Severity.MEDIUM for f in result.findings)
    has_info = any(f.severity == Severity.INFO for f in result.findings)
    if has_high:
        return Verdict.UNHEALTHY
    if has_medium:
        return Verdict.NEEDS_ATTENTION
    if result.errors:
        return Verdict.UNKNOWN
    if result.partial:
        # A run whose results / rules / artifacts live in external property
        # files was only partially analysed. Claiming `healthy` there would
        # be a claim about data this tool never read.
        return Verdict.UNKNOWN
    if has_info:
        return Verdict.NEEDS_ATTENTION if strict else Verdict.HEALTHY
    return Verdict.HEALTHY


def exit_code_for(verdict: Verdict, strict: bool = False, hard_error: bool = False) -> int:
    """Map a verdict onto the shared Convention B exit codes.

    0 healthy / 1 needs-attention / 2 unhealthy. Unreadable or unparseable
    input is a hard error and always exits 2, regardless of --strict: a CI
    job must not read "I could not open the file" as "nothing to report".
    An UNKNOWN with no hard error (no files matched, or a partially
    analysable run) exits 1 by default and 2 under --strict.
    """
    if verdict == Verdict.HEALTHY:
        return 0
    if verdict == Verdict.NEEDS_ATTENTION:
        return 1
    if verdict == Verdict.UNHEALTHY:
        return 2
    if verdict == Verdict.UNKNOWN:
        if hard_error:
            return 2
        return 2 if strict else 1
    return 1


def counts(result: ScanResult) -> Tuple[int, int, int]:
    high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
    info = sum(1 for f in result.findings if f.severity == Severity.INFO)
    return high, medium, info
