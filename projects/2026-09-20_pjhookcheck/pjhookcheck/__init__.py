"""pjhookcheck - static linter for package.json lifecycle-hook and
install-time supply-chain shapes.

Zero dependencies. Python 3.10+.
"""

__version__ = "0.1.0"

from .types import Severity, Verdict, Finding, ScanResult
from .rules import REGISTRY, Check

# The lab's shared package surface (see docs/CONVENTIONS.md) names the rule
# table ALL_RULES and the rule type Rule. This module keeps REGISTRY / Check
# as the internal spelling and exposes the shared names as aliases, so a
# consumer can rely on the same surface across every linter in the set.
ALL_RULES = REGISTRY
Rule = Check

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "ALL_RULES",
    "Rule",
    "REGISTRY",
    "Check",
]
