"""Shared datatypes for agentmemcheck.

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
    """One rule firing against one memory entry at one JSON pointer."""

    rule_id: str
    severity: Severity
    message: str
    entry_id: str
    pointer: str
    path: str = ""
    hint: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "entry_id": self.entry_id,
            "pointer": self.pointer,
            "path": self.path,
            "hint": self.hint,
        }


@dataclass
class ScanResult:
    """The outcome of scanning one or more memory-store files."""

    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    entries_scanned: int = 0
    verdict: Verdict = Verdict.UNKNOWN
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "files_scanned": self.files_scanned,
            "entries_scanned": self.entries_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


@dataclass(frozen=True)
class Options:
    """Scan-time options surfaced by the CLI."""

    strict: bool = False
    include_info: bool = False
    disabled: Tuple[str, ...] = ()
    only: Tuple[str, ...] = ()
    # External-origin tokens for AMC-003 / AMC-006. A memory entry whose
    # source field matches (case-insensitively, after tokenisation) any
    # of these is treated as untrusted-origin content.
    external_sources: Tuple[str, ...] = (
        "external", "web", "scraped", "tool", "tool_output",
        "retrieval", "rag", "search", "fetch", "untrusted",
        "user_input", "chat", "message", "page", "url", "http",
    )
    # Elevated-role tokens for AMC-003. A memory entry whose role / scope
    # field matches any of these is a higher-privilege target that must
    # not carry external-origin content.
    elevated_roles: Tuple[str, ...] = (
        "system", "developer", "instruction", "instructions",
        "persistent", "rule", "rules", "policy", "guideline",
        "guidelines", "admin",
    )
    # Soft and hard byte caps for AMC-011. The content string of a
    # single entry at or above the hard cap is unusual for a memory
    # record and is a known exfiltration-staging surface.
    oversize_cap_bytes: int = 8000
    # TTL grace window for AMC-010. A timestamp more than this many
    # seconds in the future is implausible under any reasonable clock
    # skew.
    future_grace_seconds: int = 86400

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
]
