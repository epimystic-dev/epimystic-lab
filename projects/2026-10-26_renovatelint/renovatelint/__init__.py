"""renovatelint - static linter for Renovate bot config files.

Zero dependencies. Python 3.9+.
"""

__version__ = "0.2.0"

from .rules import REGISTRY, Check, Rule
from .types import Finding, Options, ScanResult, Severity, Verdict

# The lab's shared package surface (see docs/CONVENTIONS.md) names the
# rule table ALL_RULES and the rule type Rule.
ALL_RULES = REGISTRY

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Options",
    "ALL_RULES",
    "Rule",
    "REGISTRY",
    "Check",
]
