"""aicontribcheck -- offline AI-contribution-policy detector for repositories.

Given a repository checkout, scans the canonical policy surface
(CONTRIBUTING, README, AGENTS.md, .github/*, LICENSE, etc.) for
machine-readable statements about whether AI-authored contributions
are permitted, banned, or conditional, and emits a structured verdict.

Zero runtime dependencies; pure Python stdlib.
"""

from .types import (
    Verdict,
    Severity,
    Finding,
    FileScan,
    RepoReport,
)
from .scanner import discover_policy_files, read_policy_file
from .rules import RULES, run_rules, rollup
from .report import format_text, format_json

__all__ = [
    "Verdict",
    "Severity",
    "Finding",
    "FileScan",
    "RepoReport",
    "discover_policy_files",
    "read_policy_file",
    "RULES",
    "run_rules",
    "rollup",
    "format_text",
    "format_json",
]

__version__ = "0.1.0"
