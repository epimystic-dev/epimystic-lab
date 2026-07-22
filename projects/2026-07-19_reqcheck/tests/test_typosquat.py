"""Tests for Damerau-Levenshtein + typosquat candidate detection."""

import unittest

from reqcheck.typosquat import (
    damerau_levenshtein,
    typosquat_candidate,
    POPULAR_PACKAGES,
    KNOWN_LEGITIMATE,
)


class DamerauLevenshteinTests(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(damerau_levenshtein("abc", "abc"), 0)

    def test_empty_vs_word(self):
        self.assertEqual(damerau_levenshtein("", "abc"), 3)
        self.assertEqual(damerau_levenshtein("abc", ""), 3)

    def test_single_substitution(self):
        self.assertEqual(damerau_levenshtein("abc", "abd"), 1)

    def test_single_insertion(self):
        self.assertEqual(damerau_levenshtein("abc", "abcd"), 1)

    def test_single_deletion(self):
        self.assertEqual(damerau_levenshtein("abcd", "abc"), 1)

    def test_transposition_counts_as_one(self):
        # A pure Levenshtein sees 'ab' vs 'ba' as 2 edits;
        # Damerau-Levenshtein counts it as 1.
        self.assertEqual(damerau_levenshtein("ab", "ba"), 1)

    def test_requests_typo_distance_one(self):
        self.assertEqual(damerau_levenshtein("requsts", "requests"), 1)


class TyposquatCandidateTests(unittest.TestCase):
    def test_exact_popular_returns_none(self):
        self.assertIsNone(typosquat_candidate("requests"))
        self.assertIsNone(typosquat_candidate("numpy"))

    def test_close_typo_is_flagged(self):
        hit = typosquat_candidate("requsts")
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], "requests")
        self.assertEqual(hit[1], 1)

    def test_numpi_flagged_as_numpy(self):
        hit = typosquat_candidate("numpi")
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], "numpy")

    def test_pyyml_flagged_as_pyyaml(self):
        hit = typosquat_candidate("pyyml")
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], "pyyaml")

    def test_short_name_below_min_length_returns_none(self):
        self.assertIsNone(typosquat_candidate("np"))

    def test_far_name_returns_none(self):
        # Completely unrelated
        self.assertIsNone(typosquat_candidate("myawesomeutility"))

    def test_known_legitimate_returns_none(self):
        for name in KNOWN_LEGITIMATE:
            self.assertIsNone(
                typosquat_candidate(name), f"expected {name!r} to be excluded"
            )

    def test_all_popular_entries_are_canonical(self):
        for pop in POPULAR_PACKAGES:
            self.assertEqual(pop, pop.lower())
            self.assertNotIn("_", pop)
            self.assertNotIn(".", pop)


if __name__ == "__main__":
    unittest.main()
