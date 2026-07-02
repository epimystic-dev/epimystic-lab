"""seedline - deterministic seed locking for ML/LLM tests.

One opinionated function and one context manager that seed every RNG that
matters across Python, NumPy, PyTorch, and `os.environ['PYTHONHASHSEED']`,
and undo themselves on exit.

Public API:
    seed_all(seed: int) -> SeedSnapshot
    seeded(seed: int) -> contextmanager (yields SeedSnapshot)
    snapshot() -> SeedSnapshot
    restore(snap: SeedSnapshot) -> None
    detect() -> dict[str, str]  # which backends are present and locked
"""

from .core import (
    SeedSnapshot,
    detect,
    restore,
    seed_all,
    seeded,
    snapshot,
)

__all__ = [
    "SeedSnapshot",
    "detect",
    "restore",
    "seed_all",
    "seeded",
    "snapshot",
]
__version__ = "0.1.0"
