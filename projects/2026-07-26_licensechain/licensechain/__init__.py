"""licensechain -- offline license-chain hygiene linter for AI supply chains."""

__version__ = "0.1.0"

from .spdx_data import LICENSES, is_known_id, get_license
from .expr import parse_expr, ParseError, Expr, LicenseId, With, And, Or
from .loader import load_manifest, Component, Chain, LoadError
from .rules import check_chain, Finding, Severity

__all__ = [
    "__version__",
    "LICENSES",
    "is_known_id",
    "get_license",
    "parse_expr",
    "ParseError",
    "Expr",
    "LicenseId",
    "With",
    "And",
    "Or",
    "load_manifest",
    "Component",
    "Chain",
    "LoadError",
    "check_chain",
    "Finding",
    "Severity",
]
