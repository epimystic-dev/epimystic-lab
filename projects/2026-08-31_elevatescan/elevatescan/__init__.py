"""elevatescan -- offline static scanner for instruction-privilege-escalation shapes.

Zero-dep Python stdlib linter. See README.md for scope and honest limits.
"""

from .types import Severity, Verdict, Finding, ScanResult
from .config import Config, DEFAULT_GLOBS, DEFAULT_MAX_FILES, DEFAULT_MAX_BYTES
from .rules import ALL_RULES, Rule
from .scanner import scan_path, discover, read_text, strip_bom
from .verdict import compute_verdict
from .report import render_text, render_json

__version__ = "0.1.0"

__all__ = [
    "Severity",
    "Verdict",
    "Finding",
    "ScanResult",
    "Config",
    "DEFAULT_GLOBS",
    "DEFAULT_MAX_FILES",
    "DEFAULT_MAX_BYTES",
    "ALL_RULES",
    "Rule",
    "scan_path",
    "discover",
    "read_text",
    "strip_bom",
    "compute_verdict",
    "render_text",
    "render_json",
    "__version__",
]
