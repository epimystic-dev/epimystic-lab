"""Core value types: Severity, Finding, Verdict."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    INFO = "info"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.INFO: 3,
}


class Verdict(Enum):
    HEALTHY = "healthy"
    NEEDS_ATTENTION = "needs-attention"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int = 0
    column: int = 0
    detail: str = ""

    def sort_key(self):
        return (
            SEVERITY_RANK[self.severity],
            self.path,
            self.line,
            self.column,
            self.rule_id,
        )


@dataclass
class FileReport:
    path: str
    findings: List[Finding] = field(default_factory=list)
    read_error: Optional[str] = None
    bytes_read: int = 0

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())


@dataclass
class ScanReport:
    root: str
    file_reports: List[FileReport] = field(default_factory=list)
    scan_errors: List[str] = field(default_factory=list)

    def all_findings(self) -> List[Finding]:
        out: List[Finding] = []
        for fr in self.file_reports:
            out.extend(fr.findings)
        return sorted(out, key=lambda f: f.sort_key())

    def files_scanned(self) -> int:
        return sum(1 for fr in self.file_reports if fr.read_error is None)
