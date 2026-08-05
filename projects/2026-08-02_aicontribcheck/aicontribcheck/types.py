"""Core datatypes for aicontribcheck.

Verdict is the machine-consumable rollup:
  - allowed    : at least one strong ALLOW signal, no BAN
  - banned     : at least one BAN signal
  - conditional: any CONDITIONAL signal without ALLOW/BAN dominating
  - unknown    : no relevant signal found
  - conflict   : signals disagree across files (e.g. README allows, CONTRIBUTING bans)

Severity is per-finding:
  - ERROR: contradicts safe agentic contribution (BAN, CONFLICT)
  - WARN : requires action before contributing (CONDITIONAL, missing disclosure)
  - INFO : informational signal (ALLOW confirmation, evidence citations)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Verdict(str, Enum):
    ALLOWED = "allowed"
    BANNED = "banned"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class Severity(str, Enum):
    ERROR = "error"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    verdict: Verdict
    message: str
    file: str
    line: int
    evidence: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "verdict": self.verdict.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
        }


@dataclass
class FileScan:
    path: str
    kind: str
    findings: List[Finding] = field(default_factory=list)
    read_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "kind": self.kind,
            "findings": [f.to_dict() for f in self.findings],
            "read_error": self.read_error,
        }


@dataclass
class RepoReport:
    root: str
    files_scanned: List[FileScan] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    required_disclosures: List[str] = field(default_factory=list)
    required_attributions: List[str] = field(default_factory=list)
    tools_named: List[str] = field(default_factory=list)

    def all_findings(self) -> List[Finding]:
        out = []
        for fs in self.files_scanned:
            out.extend(fs.findings)
        return out

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "verdict": self.verdict.value,
            "required_disclosures": sorted(set(self.required_disclosures)),
            "required_attributions": sorted(set(self.required_attributions)),
            "tools_named": sorted(set(self.tools_named)),
            "files": [fs.to_dict() for fs in self.files_scanned],
            "summary": self._summary(),
        }

    def _summary(self) -> dict:
        counts = {"error": 0, "warn": 0, "info": 0}
        rule_counts: dict = {}
        for fs in self.files_scanned:
            for f in fs.findings:
                counts[f.severity.value] += 1
                rule_counts[f.rule] = rule_counts.get(f.rule, 0) + 1
        return {
            "files_scanned": len(self.files_scanned),
            "counts_by_severity": counts,
            "counts_by_rule": dict(sorted(rule_counts.items())),
        }
