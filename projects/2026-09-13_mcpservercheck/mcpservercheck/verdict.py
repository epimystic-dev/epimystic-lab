"""Verdict rollup and exit-code mapping."""

from typing import Tuple

from .types import ScanResult, Severity, Verdict


def compute_verdict(result: ScanResult, strict: bool = False) -> Verdict:
    """Roll up findings into a single verdict.

    - No files scanned          -> UNKNOWN
    - Any HIGH                  -> UNHEALTHY
    - Any MEDIUM (no HIGH)      -> NEEDS_ATTENTION
    - Only INFO (no HIGH/MED)   -> HEALTHY (default), NEEDS_ATTENTION (strict)
    - No findings + files > 0   -> HEALTHY
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
    if has_info:
        return Verdict.NEEDS_ATTENTION if strict else Verdict.HEALTHY
    return Verdict.HEALTHY


def exit_code_for(verdict: Verdict, strict: bool = False) -> int:
    if verdict == Verdict.HEALTHY:
        return 0
    if verdict == Verdict.NEEDS_ATTENTION:
        return 1
    if verdict == Verdict.UNHEALTHY:
        return 2
    if verdict == Verdict.UNKNOWN:
        return 2 if strict else 1
    return 1


def counts(result: ScanResult) -> Tuple[int, int, int]:
    high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
    info = sum(1 for f in result.findings if f.severity == Severity.INFO)
    return high, medium, info
