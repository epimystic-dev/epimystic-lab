"""Shared types."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "INFO"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


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

    def sort_key(self) -> tuple:
        return (SEVERITY_RANK[self.severity], self.path, self.line, self.column, self.rule_id)

    def to_json_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
        }


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    severity: Severity
    description: str


@dataclass
class ScanResult:
    path: str
    error: Optional[str] = None
    findings: list = field(default_factory=list)
