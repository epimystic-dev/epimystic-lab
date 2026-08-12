"""skillcheck -- offline safety linter for agent skill files.

Given a repository checkout or a single file, scans a canonical set of
agent-skill locations for embedded risky patterns and emits a structured
verdict (safe | suspicious | unsafe | unknown).

Zero dependencies. Python stdlib only.
"""

from skillcheck.verdict import Verdict, Severity, Finding, Report
from skillcheck.patterns import PATTERNS, Pattern
from skillcheck.rules import evaluate_text, RULES
from skillcheck.scanner import discover_skill_files, read_skill_file, scan_path
from skillcheck.report import build_report, report_to_json, report_to_text, exit_code_for

__version__ = "0.1.0"

__all__ = [
    "Verdict",
    "Severity",
    "Finding",
    "Report",
    "PATTERNS",
    "Pattern",
    "RULES",
    "evaluate_text",
    "discover_skill_files",
    "read_skill_file",
    "scan_path",
    "build_report",
    "report_to_json",
    "report_to_text",
    "exit_code_for",
    "__version__",
]
