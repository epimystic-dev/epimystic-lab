"""nbshape: offline reproducibility-hygiene linter for Jupyter notebook JSON.

Stdlib only. Executes nothing, opens no socket, and makes no claim about
whether any notebook reproduces - it reports shapes in the stored file.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .types import NOTEBOOK_LEVEL, Finding, ScanResult, Severity, Verdict
from .rules import ALL_RULES, Rule, RuleConfig

__all__ = [
    "__version__",
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "ALL_RULES",
    "Rule",
    "RuleConfig",
    "NOTEBOOK_LEVEL",
]
