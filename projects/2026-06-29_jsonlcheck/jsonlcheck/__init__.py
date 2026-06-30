"""jsonlcheck - strict streaming JSONL validator.

Public API:
    check_stream(stream, *, options=None) -> Iterator[Issue]
    check_path(path, *, options=None) -> Iterator[Issue]
    Issue, Severity, Options
"""

from .core import (
    Issue,
    Options,
    Severity,
    check_path,
    check_stream,
    iter_lines,
)

__all__ = [
    "Issue",
    "Options",
    "Severity",
    "check_path",
    "check_stream",
    "iter_lines",
]
__version__ = "0.1.0"
