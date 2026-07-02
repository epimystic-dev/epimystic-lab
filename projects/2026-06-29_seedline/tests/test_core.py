"""Tests for seedline.core.

Run: ``python -m unittest discover -s tests``
"""

from __future__ import annotations

import os
import random
import unittest

from seedline import SeedSnapshot, detect, restore, seed_all, seeded, snapshot


class DetectShape(unittest.TestCase):
    def test_detect_has_all_required_keys(self):
        d = detect()
        for k in ("python", "numpy", "torch", "torch_cuda", "hash_seed"):
            self.assertIn(k, d)
        self.assertEqual(d["python"], "present")

    def test_detect_returns_strings_only(self):
        d = detect()
        for v in d.values():
            self.assertIsInstance(v, str)


class SeedAllValidation(unittest.TestCase):
    def test_rejects_negative(self):
        with self.assertRaises(ValueError):
            seed_all(-1)

    def test_rejects_too_large(self):
        with self.assertRaises(ValueError):
            seed_all(2**32)

    def test_rejects_non_int(self):
        with self.assertRaises(TypeError):
            seed_all(1.5)  # type: ignore[arg-type]

    def test_rejects_bool(self):
        # bool is a subclass of int; explicit rejection prevents surprise.
        with self.assertRaises(TypeError):
            seed_all(True)  # type: ignore[arg-type]

    def test_zero_is_a_valid_seed(self):
        seed_all(0)  # must not raise

    def test_max_is_valid(self):
        seed_all(2**32 - 1)  # must not raise


class StdlibRandomDeterminism(unittest.TestCase):
    def test_same_seed_same_sequence(self):
        seed_all(123)
        seq1 = [random.random() for _ in range(8)]
        seed_all(123)
        seq2 = [random.random() for _ in range(8)]
        self.assertEqual(seq1, seq2)

    def test_different_seeds_different_sequences(self):
        seed_all(1)
        seq1 = [random.random() for _ in range(8)]
        seed_all(2)
        seq2 = [random.random() for _ in range(8)]
        self.assertNotEqual(seq1, seq2)

    def test_randint_also_deterministic(self):
        seed_all(7)
        a = [random.randint(0, 1_000_000) for _ in range(20)]
        seed_all(7)
        b = [random.randint(0, 1_000_000) for _ in range(20)]
        self.assertEqual(a, b)


class SnapshotAndRestore(unittest.TestCase):
    def test_snapshot_then_restore_recovers_sequence(self):
        random.seed(999)
        snap = snapshot()
        a = [random.random() for _ in range(5)]
        # advance the state
        for _ in range(10):
            random.random()
        restore(snap)
        b = [random.random() for _ in range(5)]
        self.assertEqual(a, b)

    def test_snapshot_is_a_seed_snapshot(self):
        s = snapshot()
        self.assertIsInstance(s, SeedSnapshot)
        self.assertIsNotNone(s.python_random)

    def test_restore_is_idempotent(self):
        random.seed(42)
        snap = snapshot()
        restore(snap)
        a = random.random()
        restore(snap)  # restore again
        b = random.random()
        self.assertEqual(a, b)


class SeededContextManager(unittest.TestCase):
    def test_block_is_deterministic(self):
        with seeded(13):
            a = [random.random() for _ in range(6)]
        with seeded(13):
            b = [random.random() for _ in range(6)]
        self.assertEqual(a, b)

    def test_block_restores_prior_state_on_exit(self):
        random.seed(0)
        before = random.random()           # advance state once
        # the next random.random() from this state is the value we want back
        # after the with-block has come and gone.
        marker_state = snapshot()
        expected_next = random.random()
        # rewind to marker_state
        restore(marker_state)

        with seeded(999):
            # consume some randomness inside
            for _ in range(3):
                random.random()

        # now after the block, the outer RNG should produce expected_next
        got_next = random.random()
        self.assertEqual(got_next, expected_next)

    def test_block_restores_on_exception(self):
        random.seed(0)
        marker = snapshot()
        expected_next = random.random()
        restore(marker)

        try:
            with seeded(777):
                random.random()
                raise RuntimeError("boom")
        except RuntimeError:
            pass

        self.assertEqual(random.random(), expected_next)

    def test_yields_prior_snapshot(self):
        with seeded(5) as prior:
            self.assertIsInstance(prior, SeedSnapshot)
            self.assertIsNotNone(prior.python_random)


class NumpyOptional(unittest.TestCase):
    """Skipped silently when numpy isn't installed; verifies the integration
    when it is."""

    def setUp(self):
        try:
            import numpy as np  # noqa: F401
        except ImportError:
            self.skipTest("numpy not installed")

    def test_numpy_seed_is_deterministic(self):
        import numpy as np
        seed_all(2024)
        a = np.random.rand(8)
        seed_all(2024)
        b = np.random.rand(8)
        self.assertTrue((a == b).all())

    def test_numpy_state_restored_by_seeded_block(self):
        import numpy as np
        np.random.seed(0)
        # advance and capture marker
        np.random.rand(3)
        marker = snapshot()
        expected = np.random.rand(3).tolist()
        restore(marker)

        with seeded(42):
            np.random.rand(5)

        got = np.random.rand(3).tolist()
        self.assertEqual(got, expected)


class TorchOptional(unittest.TestCase):
    def setUp(self):
        try:
            import torch  # noqa: F401
        except ImportError:
            self.skipTest("torch not installed")

    def test_torch_seed_is_deterministic(self):
        import torch
        seed_all(31)
        a = torch.rand(8)
        seed_all(31)
        b = torch.rand(8)
        self.assertTrue(torch.equal(a, b))

    def test_torch_state_restored_by_seeded_block(self):
        import torch
        torch.manual_seed(0)
        torch.rand(3)
        marker = snapshot()
        expected = torch.rand(3).tolist()
        restore(marker)

        with seeded(9):
            torch.rand(5)

        got = torch.rand(3).tolist()
        self.assertEqual(got, expected)


class ReturnValueOfSeedAll(unittest.TestCase):
    def test_returns_a_snapshot(self):
        prior = seed_all(1)
        self.assertIsInstance(prior, SeedSnapshot)

    def test_returned_snapshot_can_round_trip(self):
        random.seed(0)
        marker = snapshot()
        expected = random.random()
        restore(marker)
        # seed and capture-prior
        prior = seed_all(123)
        # state is now the seeded-123 state; consume.
        random.random()
        # restore to the prior — i.e. our marker state.
        restore(prior)
        self.assertEqual(random.random(), expected)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
