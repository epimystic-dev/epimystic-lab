"""Tests for seedline.core.

Run: ``python -m unittest discover -s tests``
"""

from __future__ import annotations

import os
import random
import unittest
from unittest import mock

import seedline.core as _core
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


def _fake_import(absent):
    """Return a stand-in for seedline.core._try_import that pretends the
    modules named in ``absent`` are not importable, delegating to the real
    ``_try_import`` for everything else."""
    real = _core._try_import

    def fake(name):
        if name in absent:
            return None
        return real(name)

    return fake


class BackendAbsentFallbacks(unittest.TestCase):
    """The module docstring promises that when NumPy or PyTorch are not
    importable the corresponding snapshot fields stay ``None`` and every
    entry point silently skips them. The optional-backend tests above skip
    when a backend is absent from the *host* - they never exercise the
    absent-branch code paths on a machine that does have the backend. These
    tests patch ``_try_import`` so the absent branches run regardless of the
    test host's environment."""

    def test_detect_reports_numpy_absent_when_import_fails(self):
        with mock.patch.object(_core, "_try_import", new=_fake_import({"numpy"})):
            d = detect()
        self.assertEqual(d["numpy"], "absent")

    def test_detect_reports_torch_and_cuda_absent_when_import_fails(self):
        with mock.patch.object(_core, "_try_import", new=_fake_import({"torch"})):
            d = detect()
        self.assertEqual(d["torch"], "absent")
        self.assertEqual(d["torch_cuda"], "absent")

    def test_snapshot_leaves_numpy_field_none_when_numpy_absent(self):
        with mock.patch.object(_core, "_try_import", new=_fake_import({"numpy"})):
            snap = snapshot()
        self.assertIsNone(snap.numpy_random)
        # The stdlib RNG state must still be captured.
        self.assertIsNotNone(snap.python_random)

    def test_snapshot_leaves_torch_fields_none_when_torch_absent(self):
        with mock.patch.object(_core, "_try_import", new=_fake_import({"torch"})):
            snap = snapshot()
        self.assertIsNone(snap.torch_cpu)
        self.assertIsNone(snap.torch_cuda)

    def test_seed_all_returns_snapshot_when_numpy_absent(self):
        with mock.patch.object(_core, "_try_import", new=_fake_import({"numpy"})):
            prior = seed_all(1234)
        self.assertIsInstance(prior, SeedSnapshot)
        self.assertIsNone(prior.numpy_random)

    def test_seed_all_returns_snapshot_when_torch_absent(self):
        with mock.patch.object(_core, "_try_import", new=_fake_import({"torch"})):
            prior = seed_all(1234)
        self.assertIsInstance(prior, SeedSnapshot)
        self.assertIsNone(prior.torch_cpu)
        self.assertIsNone(prior.torch_cuda)

    def test_restore_skips_numpy_when_snapshot_field_is_none(self):
        """A partial-backend snapshot (captured on a numpy-less host) must not
        touch numpy state on a host that DOES have numpy - otherwise it would
        try to feed ``None`` to ``np.random.set_state`` and blow up."""
        try:
            import numpy as np
        except ImportError:
            self.skipTest("numpy not installed")

        with mock.patch.object(_core, "_try_import", new=_fake_import({"numpy"})):
            partial = snapshot()
        self.assertIsNone(partial.numpy_random)

        np.random.seed(4242)
        expected = np.random.rand(3).tolist()
        np.random.seed(4242)  # rewind numpy to the same starting point
        restore(partial)      # must NOT touch numpy state
        got = np.random.rand(3).tolist()
        self.assertEqual(got, expected)

    def test_restore_skips_torch_when_snapshot_field_is_none(self):
        try:
            import torch
        except ImportError:
            self.skipTest("torch not installed")

        with mock.patch.object(_core, "_try_import", new=_fake_import({"torch"})):
            partial = snapshot()
        self.assertIsNone(partial.torch_cpu)

        torch.manual_seed(4242)
        expected = torch.rand(3).tolist()
        torch.manual_seed(4242)
        restore(partial)
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
        # restore to the prior - i.e. our marker state.
        restore(prior)
        self.assertEqual(random.random(), expected)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
