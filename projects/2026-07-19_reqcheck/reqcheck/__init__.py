"""reqcheck: offline hygiene linter for Python pip-style requirements files.

Public surface:
    from reqcheck import parse_text, audit_file, Finding, Line
"""

from .model import Finding, Line, Location, ParsedFile
from .parser import parse_text
from .rules import audit_parsed, audit_file, RULES
from .typosquat import damerau_levenshtein, typosquat_candidate

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Line",
    "Location",
    "ParsedFile",
    "parse_text",
    "audit_parsed",
    "audit_file",
    "RULES",
    "damerau_levenshtein",
    "typosquat_candidate",
    "__version__",
]
