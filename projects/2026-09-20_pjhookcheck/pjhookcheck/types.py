"""Domain types for pjhookcheck.

A Finding is a single flagged shape in one package.json file. It carries a
text position (line and column, best effort) and a JSON property path,
which is the primary anchor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Tuple


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


def severity_rank(sev: Severity) -> int:
    return _SEV_RANK[sev]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    path: str
    prop: str
    line: int
    column: int
    message: str
    snippet: str = ""

    def sort_key(self) -> Tuple[str, int, int, str, str]:
        # Deterministic emission order: file, line, column, rule id,
        # property path. Severity is deliberately NOT part of the sort so
        # that a diff between two commits stays anchored to position.
        return (self.path, self.line, self.column, self.rule_id, self.prop)


@dataclass
class ScanResult:
    files_scanned: int = 0
    findings: Tuple[Finding, ...] = field(default_factory=tuple)
    errors: Tuple[str, ...] = field(default_factory=tuple)


@dataclass
class Options:
    disabled: FrozenSet[str] = frozenset()
    strict: bool = False
    include_info: bool = False
    max_files: int = 5000
    max_bytes: int = 5 * 1024 * 1024
