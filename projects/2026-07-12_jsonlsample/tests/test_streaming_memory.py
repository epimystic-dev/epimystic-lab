"""Verify the streaming-memory claims from the README.

The README documents three memory bounds:

- Reservoir (``-n K``)        -- O(K) memory; the sampler holds at most
                                 K records, independent of stream length.
- Bernoulli (``--fraction F``) -- O(1) memory; the sampler is a generator
                                 that yields survivors and holds no state
                                 between yields.
- Stratified (``--stratify PATH --per-group K``) -- O(g*K) memory, where g
                                 is the number of distinct groups seen.

This module drives each sampler over a ~10 MB synthetic JSONL stream and
asserts peak ``tracemalloc`` allocation stays under a budget that is
orders of magnitude below the stream size. An empirical probe measured:

- reservoir k=50   peak 268 KB (whole-file counterfactual: 31 MB)
- bernoulli f=1e-3 peak 159 KB
- stratified g=10 k=5 peak 265 KB

The 512 KB / 1 MB budgets below give ~3-4x headroom over the measured
peaks for interpreter variance across the CI matrix (Python 3.10-3.13)
while cleanly catching any regression that accumulates the input in
memory (which would peak at multiples of the stream size).

Fixture size is guarded so a shrunken writer cannot silently make the
assertion trivial.
"""

from __future__ import annotations

import os
import tempfile
import tracemalloc
import unittest

from jsonlsample.sample import (
    bernoulli_sample,
    reservoir_sample,
    stratified_reservoir_sample,
)
from jsonlsample.stream import iter_jsonl


def _write_synthetic_jsonl(path: str, *, lines: int, filler_bytes: int) -> int:
    """Write ``lines`` valid JSONL records padded to ~filler_bytes each.

    Each record carries an ``id`` and a ``group`` (id mod 10) so the same
    fixture serves the stratified probe. Returns the on-disk size in bytes.
    """
    with open(path, "wt", encoding="utf-8", newline="") as fh:
        pad = "x" * filler_bytes
        for i in range(lines):
            fh.write(f'{{"id":{i},"group":{i % 10},"pad":"{pad}"}}\n')
    return os.path.getsize(path)


def _records_from(path: str):
    """Streaming iterator of parsed records only (drops line numbers)."""
    with open(path, "rt", encoding="utf-8") as fh:
        for _, rec in iter_jsonl(fh):
            yield rec


class StreamingMemoryBound(unittest.TestCase):
    """Each sampler must not accumulate the input stream in memory."""

    def _make_fixture(self, td: str) -> tuple[str, int]:
        path = os.path.join(td, "big.jsonl")
        total_bytes = _write_synthetic_jsonl(path, lines=5000, filler_bytes=2000)
        # Guard the fixture: if the writer regresses and produces a
        # tiny file, the memory bound below would be trivially met
        # and the test would silently stop verifying anything.
        self.assertGreater(total_bytes, 9 * 1024 * 1024)
        return path, total_bytes

    def test_reservoir_peaks_under_budget_independent_of_stream_length(self):
        with tempfile.TemporaryDirectory() as td:
            path, total_bytes = self._make_fixture(td)

            tracemalloc.start()
            try:
                _ = reservoir_sample(_records_from(path), 50, seed=42)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()

            budget = 1024 * 1024  # 1 MB, ~10% of the stream size
            self.assertLess(
                peak,
                budget,
                f"reservoir_sample peak {peak} B while sampling a "
                f"{total_bytes} B stream exceeds the O(K) streaming budget "
                f"of {budget} B; the sampler is likely accumulating input",
            )

    def test_bernoulli_peaks_under_budget_when_caller_does_not_collect(self):
        with tempfile.TemporaryDirectory() as td:
            path, total_bytes = self._make_fixture(td)

            tracemalloc.start()
            try:
                # Drain with `pass` -- the sampler must not accumulate
                # yielded records internally. A 0.001 fraction yields ~5
                # records over 5000, so any drift above one-record-at-a-time
                # would show up as O(n) growth.
                for _ in bernoulli_sample(_records_from(path), 0.001, seed=42):
                    pass
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()

            budget = 512 * 1024  # 512 KB, ~5% of the stream size
            self.assertLess(
                peak,
                budget,
                f"bernoulli_sample peak {peak} B while sampling a "
                f"{total_bytes} B stream exceeds the O(1) streaming budget "
                f"of {budget} B; the sampler is likely accumulating input",
            )

    def test_stratified_peaks_under_budget_bounded_by_g_times_k(self):
        with tempfile.TemporaryDirectory() as td:
            path, total_bytes = self._make_fixture(td)

            tracemalloc.start()
            try:
                _ = stratified_reservoir_sample(
                    _records_from(path),
                    k_per_group=5,
                    key_fn=lambda r: r["group"],  # 10 distinct groups
                    seed=42,
                )
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()

            budget = 1024 * 1024  # 1 MB, ~10% of the stream size
            self.assertLess(
                peak,
                budget,
                f"stratified_reservoir_sample peak {peak} B while sampling "
                f"a {total_bytes} B stream (g=10, K=5) exceeds the O(g*K) "
                f"streaming budget of {budget} B; the sampler is likely "
                f"accumulating input",
            )


if __name__ == "__main__":
    unittest.main()
