"""Verify the streaming-memory claim from the README.

``check_stream`` / ``check_path`` are documented (README §Notes) to read
the input one line at a time and to bound memory by the longest single
line, not by the total stream length.

This test builds a ~10 MB synthetic JSONL file of many small valid
records, drains the generator without collecting the yielded ``Issue``
objects (there are none for valid input), and asserts that peak
allocation stayed under a small budget that is orders of magnitude
below the stream size.

Regression guard: an implementation that read the file whole (e.g.
``text = fh.read()`` before iterating) would peak at multiples of the
stream size. An empirical probe measured ~184 KB peak for streaming
vs ~49 MB peak for the whole-file variant on Python 3.14 -- a 260x
gap -- so the 512 KB threshold catches any real streaming regression
while leaving generous headroom for interpreter variance across the
CI matrix (3.10-3.13).
"""

from __future__ import annotations

import os
import tempfile
import tracemalloc
import unittest

from jsonlcheck import check_path


def _write_synthetic_jsonl(path: str, *, lines: int, filler_bytes: int) -> int:
    """Write ``lines`` valid JSONL records padded to ~filler_bytes each.
    Returns the resulting file size in bytes."""
    with open(path, "wt", encoding="utf-8", newline="") as fh:
        pad = "x" * filler_bytes
        for i in range(lines):
            fh.write(f'{{"id":{i},"pad":"{pad}"}}\n')
    return os.path.getsize(path)


class StreamingMemoryBound(unittest.TestCase):
    """The reader must not accumulate the stream in memory."""

    def test_ten_megabyte_stream_peaks_under_budget(self):
        # 5000 records * ~2 KB each -> ~10 MB on disk.
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "big.jsonl")
            total_bytes = _write_synthetic_jsonl(
                path, lines=5000, filler_bytes=2000
            )
            # Guard the fixture: if the writer regresses and produces a
            # tiny file, the memory bound below would be trivially met
            # and the test would silently stop verifying anything.
            self.assertGreater(total_bytes, 9 * 1024 * 1024)

            tracemalloc.start()
            try:
                # Valid input yields no Issue records, so iterating with
                # a bare ``pass`` exercises the readline + json.loads
                # hot path without any collection on the caller side.
                for _ in check_path(path):
                    pass
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()

            budget = 512 * 1024  # 512 KB, ~5% of the stream size
            self.assertLess(
                peak,
                budget,
                f"peak allocation {peak} B while reading a {total_bytes} B "
                f"stream exceeds the streaming budget of {budget} B; the "
                f"reader is likely accumulating the input in memory",
            )


if __name__ == "__main__":
    unittest.main()
