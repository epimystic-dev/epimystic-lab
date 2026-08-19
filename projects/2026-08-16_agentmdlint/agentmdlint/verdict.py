"""Verdict rollup from a scan report."""

from typing import Tuple

from .config import Config
from .types import ScanReport, Severity, Verdict


def compute_verdict(report: ScanReport, cfg: Config, strict: bool = False) -> Tuple[Verdict, int]:
    """Return (verdict, exit_code).

    exit_code mapping:
      HEALTHY         -> 0
      NEEDS_ATTENTION -> 1
      UNHEALTHY       -> 2
      UNKNOWN         -> 1 default / 2 strict
    Findings-only info escalates NEEDS_ATTENTION under --strict.
    """
    findings = report.all_findings()

    has_high = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
    has_medium = any(f.severity == Severity.MEDIUM for f in findings)
    has_info = any(f.severity == Severity.INFO for f in findings)

    if has_high:
        return Verdict.UNHEALTHY, 2

    if has_medium:
        return Verdict.NEEDS_ATTENTION, 1

    if report.files_scanned() == 0:
        return Verdict.UNKNOWN, 2 if strict else 1

    if has_info:
        return Verdict.NEEDS_ATTENTION if strict else Verdict.HEALTHY, 1 if strict else 0

    return Verdict.HEALTHY, 0
