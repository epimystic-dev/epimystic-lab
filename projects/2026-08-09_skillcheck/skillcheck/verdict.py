"""Verdict / severity / finding / report data structures.

Deliberately dataclass-based, zero-dep, easy to serialize as JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Tuple


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"


class Verdict(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.INFO: 3,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    column: int
    excerpt: str
    message: str

    def sort_key(self) -> Tuple[int, str, int, int, str]:
        return (
            SEVERITY_ORDER[self.severity],
            self.file,
            self.line,
            self.column,
            self.rule_id,
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    verdict: Verdict
    findings: List[Finding] = field(default_factory=list)
    files_scanned: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": list(self.files_scanned),
            "errors": list(self.errors),
            "summary": self.summary(),
        }

    def summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return {
            "total_findings": len(self.findings),
            "files_scanned": len(self.files_scanned),
            "by_severity": counts,
        }
