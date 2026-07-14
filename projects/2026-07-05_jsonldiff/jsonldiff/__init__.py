"""jsonldiff -- semantic diff between two JSONL streams.

Independent implementation. Zero runtime dependencies. Pure standard library.
"""

from .core import (
    Change,
    diff_files,
    diff_records,
    diff_streams,
)

__all__ = ["Change", "diff_files", "diff_records", "diff_streams"]
__version__ = "0.1.0"
