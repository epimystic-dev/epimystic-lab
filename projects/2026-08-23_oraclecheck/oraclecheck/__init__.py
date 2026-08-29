"""oraclecheck: offline AST linter for state-anchored test oracles in Python."""

from oraclecheck.types import Finding, Severity, Verdict
from oraclecheck.rules import ALL_RULES, RULE_REGISTRY, evaluate_module
from oraclecheck.scanner import scan_path, discover_test_files, read_source
from oraclecheck.report import build_report, render_json, render_text
from oraclecheck.verdict import rollup_verdict

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Severity",
    "Verdict",
    "ALL_RULES",
    "RULE_REGISTRY",
    "evaluate_module",
    "scan_path",
    "discover_test_files",
    "read_source",
    "build_report",
    "render_json",
    "render_text",
    "rollup_verdict",
    "__version__",
]
