from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


SEVERITY_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.INFO: 2}


class Verdict(str, Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    path: str
    line: int
    column: int
    message: str
    evidence: str

    def sort_key(self) -> Tuple[int, str, int, int, str]:
        return (
            SEVERITY_RANK[self.severity],
            self.path,
            self.line,
            self.column,
            self.rule_id,
        )


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors: List[Tuple[str, str]] = field(default_factory=list)
