from __future__ import annotations

from .config import Config
from .types import ScanResult, Severity, Verdict


def compute_verdict(result: ScanResult, config: Config) -> Verdict:
    """Fold findings + scan state into a single verdict.

    Rules:
    - path missing / no files scanned -> UNKNOWN
    - any HIGH severity finding -> UNHEALTHY
    - any MEDIUM (no HIGH) -> NEEDS_ATTENTION
    - INFO only, strict mode -> NEEDS_ATTENTION
    - INFO only, default -> HEALTHY
    - no findings + files scanned -> HEALTHY
    """
    if result.files_scanned == 0:
        return Verdict.UNKNOWN
    has_high = False
    has_medium = False
    has_info = False
    for f in result.findings:
        if f.severity == Severity.HIGH:
            has_high = True
        elif f.severity == Severity.MEDIUM:
            has_medium = True
        elif f.severity == Severity.INFO:
            has_info = True
    if has_high:
        return Verdict.UNHEALTHY
    if has_medium:
        return Verdict.NEEDS_ATTENTION
    if has_info and config.strict:
        return Verdict.NEEDS_ATTENTION
    return Verdict.HEALTHY


def exit_code(verdict: Verdict, config: Config) -> int:
    if verdict == Verdict.UNHEALTHY:
        return 2
    if verdict == Verdict.NEEDS_ATTENTION:
        return 1
    if verdict == Verdict.UNKNOWN:
        return 2 if config.strict else 1
    return 0
