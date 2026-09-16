"""Domain types for delegcheck."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class Verdict(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


_SEV_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.INFO: 2}


def severity_rank(sev):
    return _SEV_RANK[sev]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    path: str
    line: int
    column: int
    message: str
    snippet: str

    def sort_key(self):
        return (
            severity_rank(self.severity),
            self.path,
            self.line,
            self.column,
            self.rule_id,
        )


@dataclass
class ScanResult:
    files_scanned: int = 0
    findings: Tuple[Finding, ...] = field(default_factory=tuple)
    errors: Tuple[str, ...] = field(default_factory=tuple)
