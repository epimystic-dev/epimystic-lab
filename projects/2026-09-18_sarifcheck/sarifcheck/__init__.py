"""sarifcheck: offline linter for SARIF 2.1.0 result files.

Checks a named, documented subset of SARIF 2.1.0 property paths plus one
vendor's published code-scanning ingest ceilings. It is NOT a JSON Schema
validator and a clean run does not mean any endpoint will accept the file.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .types import Finding, Options, Profile, ScanResult, Severity, Verdict
from .rules import ALL_RULES, Rule

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Profile",
    "Finding",
    "ScanResult",
    "Options",
    "ALL_RULES",
    "Rule",
]
