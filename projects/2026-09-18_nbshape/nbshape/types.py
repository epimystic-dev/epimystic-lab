"""Domain types for nbshape.

Three severities (HIGH / MEDIUM / INFO) roll up into one of four verdicts
(healthy / needs-attention / unhealthy / unknown). The rollup itself lives in
verdict.py; this module only defines the vocabulary and the finding record.
"""

from __future__ import annotations

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
    """Sort rank for a severity. Lower sorts first (HIGH before INFO)."""
    return _SEV_RANK[sev]


#: Sentinel for a finding that belongs to the notebook as a whole rather than
#: to any single cell (for example a metadata or nbformat-level defect).
NOTEBOOK_LEVEL = -1


@dataclass(frozen=True)
class Finding:
    """One rule hit.

    ``line`` / ``column`` are a best-effort 1-indexed position inside the
    .ipynb file itself, located by searching the raw JSON text for the
    offending literal. They fall back to (1, 1) when the literal cannot be
    located - the JSON escaping of a source line is not always recoverable.
    ``cell`` is the 0-indexed position of the owning cell in the stored
    ``cells`` array, or NOTEBOOK_LEVEL for a whole-file finding.
    """

    rule_id: str
    severity: Severity
    path: str
    cell: int
    line: int
    column: int
    message: str
    snippet: str

    def sort_key(self):
        return (
            severity_rank(self.severity),
            self.path,
            self.cell,
            self.line,
            self.column,
            self.rule_id,
        )

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "path": self.path,
            "cell": self.cell,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
        }


@dataclass
class ScanResult:
    """Aggregate of one run.

    ``files_scanned``  every .ipynb the walk opened.
    ``files_scored``   the subset that passed the NBK-010 conformance gate and
                       therefore had the remaining rules applied to them.
    ``files_unknown``  the subset that did not - unreadable, over the byte cap,
                       not JSON, or not a schema-conformant v4 notebook. These
                       route the verdict to ``unknown`` rather than to a
                       severity, because no rule's field assumptions hold.
    """

    files_scanned: int = 0
    files_scored: int = 0
    files_unknown: int = 0
    findings: Tuple[Finding, ...] = field(default_factory=tuple)
    errors: Tuple[str, ...] = field(default_factory=tuple)
