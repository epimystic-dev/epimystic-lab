"""Verdict rollup and exit-code mapping for nbshape.

The rollup is a verdict wrapper over severity tiers - Convention B in
epimystic-lab/docs/CONVENTIONS.md - with one addition specific to this tool:
a file that fails the NBK-010 conformance gate is not scored at all, so a run
in which nothing could be scored rolls up to ``unknown`` rather than to a
severity nobody measured.
"""

from __future__ import annotations

from typing import Tuple

from .types import ScanResult, Severity, Verdict


def compute_verdict(result: ScanResult, strict: bool = False) -> Verdict:
    """Roll findings up into a single verdict.

    Order of precedence:

    1. No files scanned at all           -> UNKNOWN
    2. Any HIGH finding                  -> UNHEALTHY
    3. Any MEDIUM finding                -> NEEDS_ATTENTION
    4. Files were opened but none scored -> UNKNOWN
    5. Only INFO findings                -> HEALTHY, or NEEDS_ATTENTION under --strict
    6. Otherwise                         -> HEALTHY

    Steps 2 and 3 sit above step 4 on purpose: if one notebook in a directory
    was scorable and unhealthy, the run is unhealthy even when a sibling file
    was unreadable.
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
    if result.files_scored <= 0:
        return Verdict.UNKNOWN
    if has_info:
        return Verdict.NEEDS_ATTENTION if strict else Verdict.HEALTHY
    return Verdict.HEALTHY


def exit_code_for(verdict: Verdict, strict: bool = False) -> int:
    """Map a verdict to a process exit code.

    0 healthy, 1 needs-attention, 2 unhealthy. ``unknown`` is 1 by default and
    2 under --strict, matching the other verdict-rollup linters in the lab.
    """
    if verdict == Verdict.HEALTHY:
        return 0
    if verdict == Verdict.NEEDS_ATTENTION:
        return 1
    if verdict == Verdict.UNHEALTHY:
        return 2
    if verdict == Verdict.UNKNOWN:
        return 2 if strict else 1
    return 1  # pragma: no cover - defensive


def counts(result: ScanResult) -> Tuple[int, int, int]:
    """(high, medium, info) finding counts."""
    high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
    info = sum(1 for f in result.findings if f.severity == Severity.INFO)
    return high, medium, info
