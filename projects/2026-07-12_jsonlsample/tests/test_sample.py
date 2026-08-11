import statistics
import unittest

from jsonlsample.sample import (
    bernoulli_sample,
    reservoir_sample,
    stratified_reservoir_sample,
)


class TestReservoirSample(unittest.TestCase):
    def test_k_zero(self):
        self.assertEqual(reservoir_sample(range(100), 0), [])

    def test_k_negative_raises(self):
        with self.assertRaises(ValueError):
            reservoir_sample(range(10), -1)

    def test_stream_shorter_than_k_returns_all(self):
        self.assertEqual(reservoir_sample([1, 2, 3], 5), [1, 2, 3])

    def test_stream_exact_k_returns_all(self):
        self.assertEqual(reservoir_sample([1, 2, 3, 4], 4), [1, 2, 3, 4])

    def test_size_of_sample_equals_k_when_n_ge_k(self):
        self.assertEqual(len(reservoir_sample(range(1000), 50)), 50)

    def test_deterministic_given_same_seed(self):
        a = reservoir_sample(range(1000), 50, seed=42)
        b = reservoir_sample(range(1000), 50, seed=42)
        self.assertEqual(a, b)

    def test_different_seeds_yield_different_samples(self):
        a = reservoir_sample(range(1000), 50, seed=1)
        b = reservoir_sample(range(1000), 50, seed=2)
        self.assertNotEqual(a, b)

    def test_sample_items_are_from_input(self):
        items = list(range(500))
        sample = reservoir_sample(items, 25, seed=7)
        for x in sample:
            self.assertIn(x, items)

    def test_sample_has_no_duplicates(self):
        sample = reservoir_sample(range(500), 100, seed=13)
        self.assertEqual(len(sample), len(set(sample)))

    def test_uniformity_first_moment(self):
        # Empirical check that reservoir_sample is uniform: sample means of
        # k=10 draws from 0..999 across many seeds should hug the true mean
        # of 499.5. Loose tolerance to avoid flakiness.
        n = 1000
        k = 10
        trials = 300
        means = []
        for seed in range(trials):
            s = reservoir_sample(range(n), k, seed=seed)
            means.append(statistics.mean(s))
        grand_mean = statistics.mean(means)
        # Analytical mean is (n-1)/2 = 499.5.
        # SD of one sample mean is sqrt(var / k). var of uniform int 0..n-1
        # is (n^2 - 1) / 12 ≈ 83333. SD/mean ≈ sqrt(8333.3) ≈ 91.3, so SE
        # over `trials` trials is 91.3/sqrt(300) ≈ 5.3.
        # Tolerance of 25 is ~5x SE - very loose to avoid flake.
        self.assertLess(abs(grand_mean - 499.5), 25.0)


class TestBernoulliSample(unittest.TestCase):
    def test_fraction_zero_yields_nothing(self):
        self.assertEqual(list(bernoulli_sample(range(100), 0.0)), [])

    def test_fraction_one_yields_everything(self):
        self.assertEqual(list(bernoulli_sample(range(100), 1.0)), list(range(100)))

    def test_fraction_out_of_range_raises(self):
        with self.assertRaises(ValueError):
            list(bernoulli_sample(range(10), 1.5))
        with self.assertRaises(ValueError):
            list(bernoulli_sample(range(10), -0.1))

    def test_expected_count_within_binomial_tolerance(self):
        n = 10_000
        p = 0.10
        got = sum(1 for _ in bernoulli_sample(range(n), p, seed=99))
        expected = n * p
        sd = (n * p * (1 - p)) ** 0.5
        # 6-sigma window: probability of failure on any single run is
        # negligibly small; we tighten from arbitrary tolerance to a
        # principled one.
        self.assertLess(abs(got - expected), 6 * sd)

    def test_deterministic_given_same_seed(self):
        a = list(bernoulli_sample(range(1000), 0.3, seed=5))
        b = list(bernoulli_sample(range(1000), 0.3, seed=5))
        self.assertEqual(a, b)

    def test_streaming_lazy(self):
        # If the sampler pre-consumes, this would loop forever.
        def infinite():
            i = 0
            while True:
                yield i
                i += 1

        it = bernoulli_sample(infinite(), 0.01, seed=1)
        first_five = []
        for x in it:
            first_five.append(x)
            if len(first_five) >= 5:
                break
        self.assertEqual(len(first_five), 5)


class TestStratifiedReservoirSample(unittest.TestCase):
    def test_k_zero(self):
        self.assertEqual(
            stratified_reservoir_sample(range(100), 0, lambda x: x % 2),
            [],
        )

    def test_k_negative_raises(self):
        with self.assertRaises(ValueError):
            stratified_reservoir_sample(range(10), -1, lambda x: x % 2)

    def test_one_group_matches_reservoir(self):
        out = stratified_reservoir_sample(range(10), 5, lambda x: "same", seed=3)
        keys = [k for k, _ in out]
        items = [v for _, v in out]
        self.assertTrue(all(k == "same" for k in keys))
        self.assertEqual(sorted(items), sorted(reservoir_sample(range(10), 5, seed=3)))

    def test_group_size_capped(self):
        # Two groups (even / odd) x k=3.
        out = stratified_reservoir_sample(range(100), 3, lambda x: x % 2, seed=1)
        even = [v for k, v in out if k == 0]
        odd = [v for k, v in out if k == 1]
        self.assertEqual(len(even), 3)
        self.assertEqual(len(odd), 3)
        for x in even:
            self.assertEqual(x % 2, 0)
        for x in odd:
            self.assertEqual(x % 2, 1)

    def test_group_smaller_than_k_returned_whole(self):
        items = [0, 0, 1]
        out = stratified_reservoir_sample(items, 5, lambda x: x)
        # Group 0 has 2 items, group 1 has 1 item. Both fit under k=5.
        self.assertEqual(sorted((k, v) for k, v in out), [(0, 0), (0, 0), (1, 1)])

    def test_key_fn_error_does_not_propagate(self):
        def bad_key(x):
            if x == 3:
                raise RuntimeError("boom")
            return x % 2

        out = stratified_reservoir_sample(range(6), 2, bad_key)
        keys = [k for k, _ in out]
        self.assertIn(("__error__", "RuntimeError"), keys)

    def test_deterministic_given_same_seed(self):
        a = stratified_reservoir_sample(range(500), 3, lambda x: x % 4, seed=11)
        b = stratified_reservoir_sample(range(500), 3, lambda x: x % 4, seed=11)
        self.assertEqual(a, b)

    def test_group_first_seen_order_preserved(self):
        items = ["z", "z", "a", "z", "a", "b", "z", "a", "b"]
        out = stratified_reservoir_sample(items, 1, lambda x: x, seed=0)
        keys_in_order = []
        for k, _ in out:
            if k not in keys_in_order:
                keys_in_order.append(k)
        self.assertEqual(keys_in_order, ["z", "a", "b"])


if __name__ == "__main__":
    unittest.main()
