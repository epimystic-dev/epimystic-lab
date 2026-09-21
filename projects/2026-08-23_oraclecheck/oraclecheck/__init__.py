"""oraclecheck: offline AST linter for state-anchored test oracles in Python."""

from oraclecheck.types import Finding, Severity, Verdict, ScanResult, RuleSpec
from oraclecheck.rules import ALL_RULES, RULE_REGISTRY, evaluate_module

# The lab's shared package surface (docs/CONVENTIONS.md) names the rule type
# Rule. This module keeps RuleSpec as the internal spelling and exposes Rule as
# an alias so a consumer sees the same surface across every linter in the set.
#
# Note the one divergence that is NOT aliased away: oraclecheck's ALL_RULES is
# a list of rule-id strings, while every other linter's is a list of rule
# objects. Re-typing a published export would break existing consumers, so it
# is left as-is and deferred to a major version bump.
Rule = RuleSpec
from oraclecheck.scanner import scan_path, discover_test_files, read_source
from oraclecheck.report import build_report, render_json, render_text
from oraclecheck.verdict import rollup_verdict

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Severity",
    "Verdict",
    "ScanResult",
    "RuleSpec",
    "Rule",
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
