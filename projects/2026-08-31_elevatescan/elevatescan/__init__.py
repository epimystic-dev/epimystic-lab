"""elevatescan -- offline static scanner for instruction-privilege-escalation shapes.

Zero-dep Python stdlib linter. See README.md for scope and honest limits.
"""

# __version__ is assigned BEFORE the submodule imports because report.py
# imports it via `from . import __version__` to stamp the JSON payload.
# If assignment happened after the submodule imports (the pre-0.3.0 layout),
# `from .report import ...` would load report.py while the package was still
# half-initialized and `elevatescan.__version__` would not yet exist.
__version__ = "0.3.0"

from .types import Severity, Verdict, Finding, ScanResult
from .config import Config, DEFAULT_GLOBS, DEFAULT_MAX_FILES, DEFAULT_MAX_BYTES
from .rules import ALL_RULES, Rule
from .scanner import scan_path, discover, read_text, strip_bom
from .verdict import compute_verdict
from .report import render_text, render_json

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
