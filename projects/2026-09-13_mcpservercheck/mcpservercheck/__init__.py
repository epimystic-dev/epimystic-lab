"""mcpservercheck: offline static linter for MCP-server registration config files."""

__version__ = "0.1.0"

from .types import Severity, Verdict, Finding, ScanResult
from .rules import ALL_RULES, Rule

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "ALL_RULES",
    "Rule",
]
