"""Minimal seedline demo. Run from the project root:

    python examples/demo.py

Works from a fresh clone (no install needed) - the sys.path shim below
puts the sibling package directory on the import path.

Exercises the three shapes users actually reach for: the one-line
top-of-program seed_all, the scoped `seeded()` context manager that
restores prior state on exit, and detect() as a test-suite banner.
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from seedline import detect, seed_all, seeded  # noqa: E402


def main() -> None:
    print("backends:", detect())

    # 1) Global seed at program start. Returns the pre-seed snapshot
    #    so a caller can restore later if it wants to.
    seed_all(42)
    print("seed_all(42) then random.random() ->", random.random())

    # 2) Non-deterministic block: consume a value without controlling
    #    the seed, so a subsequent `seeded()` block has something
    #    real to hide.
    _ = random.random()
    outside_before = random.random()
    print("random.random() outside seeded() ->", outside_before)

    # 3) Scope-limited determinism. Inside the block the RNG is
    #    seeded to 0; on exit, prior state is restored so the
    #    surrounding stream is undisturbed.
    with seeded(0):
        inside = random.random()
    outside_after = random.random()
    print("random.random() inside seeded(0) ->", inside)
    print("random.random() after seeded() ->", outside_after)

    # 4) `seeded(0)` must be reproducible.
    with seeded(0):
        inside_again = random.random()
    print("random.random() inside seeded(0) again ->", inside_again)
    assert inside == inside_again, "seeded(0) is not reproducible"

    print("demo OK")


if __name__ == "__main__":
    main()
