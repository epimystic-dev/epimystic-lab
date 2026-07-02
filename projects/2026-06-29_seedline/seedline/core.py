"""Deterministic seed locking across stdlib `random`, NumPy, and PyTorch.

This module exposes one job: when a test (or any code path) calls
``seed_all(seed)``, every RNG that exists in the running interpreter is
seeded to the same value so the run is reproducible. When the corresponding
``seeded(seed)`` context manager exits, the previous RNG states are restored
so the call has no global side effects beyond its scope.

Backends are detected at runtime. NumPy and PyTorch are *optional*; if they
are not importable, the corresponding fields of the snapshot are ``None``
and seeding silently skips them. ``detect()`` returns a dict that reports
exactly which backends were locked.

Design notes
~~~~~~~~~~~~

* ``random.getstate()`` / ``random.setstate()`` are exact round-trips, so
  the stdlib RNG is always restored faithfully.
* For NumPy we capture ``np.random.get_state()`` (legacy ``RandomState``)
  because that is what is mutated by ``np.random.seed`` and what most
  test suites still touch. The newer ``Generator`` API takes a fresh
  ``np.random.default_rng(seed)`` from the caller and is not global; it
  needs no save/restore.
* For PyTorch we capture both the CPU RNG state and (if available)
  per-device CUDA states. ``torch.use_deterministic_algorithms(True)`` is
  NOT toggled by this module: that switch has performance and operator-
  coverage implications that should be the caller's choice. The README
  documents how to opt in.
* ``PYTHONHASHSEED`` cannot be changed for the current process after
  interpreter start; we read it for the snapshot but cannot restore it.
  Callers who need a deterministic hash seed must set it before launching
  Python.
"""

from __future__ import annotations

import contextlib
import os
import random
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class SeedSnapshot:
    """Captured RNG state. Restore with :func:`restore`."""

    python_random: tuple
    numpy_random: Optional[tuple] = None
    torch_cpu: Optional[Any] = None
    torch_cuda: Optional[list] = None
    python_hash_seed: Optional[str] = None  # informational only


def _try_import(name: str):
    try:
        return __import__(name)
    except ImportError:
        return None


def detect() -> Dict[str, str]:
    """Return a small dict of which backends are present and their status.

    Keys: ``python``, ``numpy``, ``torch``, ``torch_cuda``, ``hash_seed``.
    Values are short strings: ``"present"``, ``"absent"``, or version-ish
    detail. Always returns a value for every key; never raises."""
    out: Dict[str, str] = {"python": "present"}

    np = _try_import("numpy")
    out["numpy"] = f"present ({np.__version__})" if np is not None else "absent"

    th = _try_import("torch")
    if th is None:
        out["torch"] = "absent"
        out["torch_cuda"] = "absent"
    else:
        out["torch"] = f"present ({th.__version__})"
        try:
            n = th.cuda.device_count()
            out["torch_cuda"] = f"present ({n} device(s))" if n else "no-devices"
        except Exception:
            out["torch_cuda"] = "no-devices"

    hs = os.environ.get("PYTHONHASHSEED")
    out["hash_seed"] = f"present ({hs})" if hs is not None else "absent"

    return out


def snapshot() -> SeedSnapshot:
    """Capture the current RNG states across detected backends."""
    snap = SeedSnapshot(
        python_random=random.getstate(),
        python_hash_seed=os.environ.get("PYTHONHASHSEED"),
    )

    np = _try_import("numpy")
    if np is not None:
        snap.numpy_random = np.random.get_state()

    th = _try_import("torch")
    if th is not None:
        snap.torch_cpu = th.random.get_rng_state()
        try:
            if th.cuda.device_count():
                snap.torch_cuda = [
                    th.cuda.get_rng_state(i) for i in range(th.cuda.device_count())
                ]
        except Exception:
            snap.torch_cuda = None

    return snap


def restore(snap: SeedSnapshot) -> None:
    """Restore RNG states captured by :func:`snapshot`. Idempotent."""
    random.setstate(snap.python_random)

    if snap.numpy_random is not None:
        np = _try_import("numpy")
        if np is not None:
            np.random.set_state(snap.numpy_random)

    if snap.torch_cpu is not None:
        th = _try_import("torch")
        if th is not None:
            th.random.set_rng_state(snap.torch_cpu)
            if snap.torch_cuda is not None:
                try:
                    for i, st in enumerate(snap.torch_cuda):
                        th.cuda.set_rng_state(st, device=i)
                except Exception:
                    pass


def seed_all(seed: int) -> SeedSnapshot:
    """Seed every RNG and return a snapshot of the *prior* state.

    Validates that ``seed`` is a non-negative integer in the 32-bit range,
    which is the intersection of what NumPy's legacy ``RandomState`` and
    ``torch.manual_seed`` accept on every platform.
    """
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError(f"seed must be a non-bool int, got {type(seed).__name__}")
    if not (0 <= seed < 2**32):
        raise ValueError(f"seed must be in [0, 2**32); got {seed}")

    prior = snapshot()

    random.seed(seed)

    np = _try_import("numpy")
    if np is not None:
        np.random.seed(seed)

    th = _try_import("torch")
    if th is not None:
        th.manual_seed(seed)
        try:
            if th.cuda.device_count():
                th.cuda.manual_seed_all(seed)
        except Exception:
            pass

    return prior


@contextlib.contextmanager
def seeded(seed: int):
    """Context manager: seed everything for the body, restore on exit.

    >>> with seeded(0):
    ...     # deterministic block
    ...     ...
    """
    prior = seed_all(seed)
    try:
        yield prior
    finally:
        restore(prior)
