"""jsonlsample: deterministic sampling for JSONL streams."""

from jsonlsample.sample import (
    bernoulli_sample,
    reservoir_sample,
    stratified_reservoir_sample,
)
from jsonlsample.stream import ParseErrorRecord, iter_jsonl, resolve_path

__version__ = "0.1.0"

__all__ = [
    "ParseErrorRecord",
    "bernoulli_sample",
    "iter_jsonl",
    "reservoir_sample",
    "resolve_path",
    "stratified_reservoir_sample",
    "__version__",
]
