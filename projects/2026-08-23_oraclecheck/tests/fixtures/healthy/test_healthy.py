"""Fixture: healthy test file with well-anchored oracles."""

import unittest


class TestArithmetic(unittest.TestCase):

    def test_add(self):
        # Expected value is a literal (specification-anchored, not state-anchored)
        self.assertEqual(2 + 3, 5)

    def test_negate(self):
        self.assertEqual(-(-7), 7)

    def test_string_concat(self):
        self.assertEqual("a" + "b", "ab")


if __name__ == "__main__":
    unittest.main()
