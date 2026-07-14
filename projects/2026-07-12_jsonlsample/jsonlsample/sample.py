"""Sampling algorithms for JSONL streams.

Three primitives:

- `reservoir_sample(stream, k, seed)` -- uniform sample of size k over an
  unknown-length stream (Vitter, 1985, Algorithm R). O(n) time, O(k)
  memory. The returned list preserves *insertion order into the
  reservoir* -- which for k >= n is source order, and for k < n is the
  order in which surviving items were placed. If the caller needs strict
  source-order preservation regardless, they can sort by the emitted
  `source_index` field via the CLI.

- `bernoulli_sample(stream, fraction, seed)` -- yield each record
  independently with probability `fraction`. Streaming (O(1) memory);
  actual sample size is Binomial(n, fraction), not exactly `fraction*n`.

- `stratified_reservoir_sample(stream, k_per_group, key_fn, seed)` --
  independent reservoir of size `k_per_group` per distinct group key.
  O(g*k) memory where g is the number of groups seen. Preserves the same
  ordering discipline as `reservoir_sample` inside each stratum.

All algorithms take an explicit `seed` for reproducibility. Two calls
with the same seed and the same input yield the same output.
"""

from __future__ import annotations

import random
from typing import Any, Callable, Iterable, List, Tuple


def _rng(seed: int) -> random.Random:
    """Isolated PRNG so we never touch the global `random.random` state."""
    return random.Random(seed)


def reservoir_sample(
    stream: Iterable[Any],
    k: int,
    seed: int = 0,
) -> List[Any]:
    """Vitter's Algorithm R: uniform random sample of size k from `stream`.

    Parameters
    ----------
    stream : iterable
        Any iterable of items.
    k : int
        Target sample size. If the stream contains n < k items, all n are
        returned.
    seed : int
        PRNG seed for reproducibility.

    Returns
    -------
    list
        Up to k items; deterministic given (input, k, seed).
    """
    if k < 0:
        raise ValueError("k must be non-negative")
    if k == 0:
        # Consume the stream anyway? No -- keep O(k) memory promise and
        # avoid side effects; but do return quickly.
        return []
    rng = _rng(seed)
    reservoir: List[Any] = []
    for i, item in enumerate(stream):
        if i < k:
            reservoir.append(item)
        else:
            # Pick a uniform index in [0, i]; if it lands in the reservoir,
            # evict that slot.
            j = rng.randint(0, i)
            if j < k:
                reservoir[j] = item
    return reservoir


def bernoulli_sample(
    stream: Iterable[Any],
    fraction: float,
    seed: int = 0,
):
    """Yield each item independently with probability `fraction`.

    Parameters
    ----------
    stream : iterable
    fraction : float in [0.0, 1.0]
    seed : int

    Yields
    ------
    items from `stream` that survived the coin flip; laziness preserved.
    """
    if not (0.0 <= fraction <= 1.0):
        raise ValueError("fraction must be in [0.0, 1.0]")
    if fraction == 0.0:
        return
    rng = _rng(seed)
    if fraction == 1.0:
        for item in stream:
            yield item
        return
    for item in stream:
        if rng.random() < fraction:
            yield item


def stratified_reservoir_sample(
    stream: Iterable[Any],
    k_per_group: int,
    key_fn: Callable[[Any], Any],
    seed: int = 0,
) -> List[Tuple[Any, Any]]:
    """Independent reservoir sample of size `k_per_group` per group key.

    Parameters
    ----------
    stream : iterable
    k_per_group : int
    key_fn : callable(item) -> group_key
        Return value must be hashable. Items whose key_fn raises are
        treated as belonging to the group `("__error__", type(exc).__name__)`
        so the caller can decide how to handle them; no exception is
        propagated out.
    seed : int

    Returns
    -------
    list of (group_key, item) pairs, in the internal reservoir order of
    each group; groups appear in first-seen order.
    """
    if k_per_group < 0:
        raise ValueError("k_per_group must be non-negative")
    if k_per_group == 0:
        return []
    rng = _rng(seed)
    reservoirs: dict[Any, List[Any]] = {}
    counters: dict[Any, int] = {}
    group_order: List[Any] = []

    for item in stream:
        try:
            key = key_fn(item)
        except Exception as exc:  # noqa: BLE001 -- documented contract
            key = ("__error__", type(exc).__name__)
        if key not in reservoirs:
            reservoirs[key] = []
            counters[key] = 0
            group_order.append(key)
        idx = counters[key]
        r = reservoirs[key]
        if idx < k_per_group:
            r.append(item)
        else:
            j = rng.randint(0, idx)
            if j < k_per_group:
                r[j] = item
        counters[key] = idx + 1

    out: List[Tuple[Any, Any]] = []
    for key in group_order:
        for item in reservoirs[key]:
            out.append((key, item))
    return out
