"""Shared datatypes for renovatelint.

Severity, Verdict, Finding, ScanResult, and Options are the shape
surface the rest of the package - and the lab-wide shared contract -
agrees on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class Verdict(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    """One rule firing against one renovate config file at one JSON pointer."""

    rule_id: str
    severity: Severity
    message: str
    pointer: str
    path: str = ""
    hint: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "pointer": self.pointer,
            "path": self.path,
            "hint": self.hint,
        }


@dataclass
class ScanResult:
    """The outcome of scanning one or more renovate config files."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    error: Optional[str] = None
    # Optional display label for the invocation (e.g. the comma-joined
    # list of CLI paths). Default "" so direct-library callers that
    # constructed ScanResult without this field continue to work.
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


# The industry-recommended quarantine window below which RNV-010 fires.
# Compass Security 2026, safeguard.sh 2026, and Renovate's own 2026
# security-mode preset discussion converge on 7 days as the practical
# floor and 14 days as the preferred value.
DEFAULT_MIN_QUARANTINE_DAYS = 7


@dataclass(frozen=True)
class Options:
    """Scan-time options surfaced by the CLI."""

    strict: bool = False
    include_info: bool = False
    disabled: Tuple[str, ...] = ()
    only: Tuple[str, ...] = ()
    min_quarantine_days: int = DEFAULT_MIN_QUARANTINE_DAYS

    def rule_enabled(self, rule_id: str) -> bool:
        if self.only and rule_id not in self.only:
            return False
        if rule_id in self.disabled:
            return False
        return True


__all__ = [
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Options",
    "DEFAULT_MIN_QUARANTINE_DAYS",
]
