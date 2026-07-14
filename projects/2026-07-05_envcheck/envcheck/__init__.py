"""envcheck -- drift and secret checks for .env / .env.example files.

Independent implementation. Zero runtime dependencies. Pure standard library.
"""

from .core import (
    Diagnostic,
    ParseResult,
    check,
    check_files,
    parse,
    parse_bytes,
)

__all__ = [
    "Diagnostic",
    "ParseResult",
    "check",
    "check_files",
    "parse",
    "parse_bytes",
]

__version__ = "0.1.0"
