"""jwtcheck: JWT / auth-secret hygiene linter for .env files."""

from jwtcheck.audit import Finding, audit_env, audit_file
from jwtcheck.parse import EnvEntry, ParseError, parse_env

__version__ = "0.1.0"

__all__ = [
    "EnvEntry",
    "Finding",
    "ParseError",
    "audit_env",
    "audit_file",
    "parse_env",
    "__version__",
]
