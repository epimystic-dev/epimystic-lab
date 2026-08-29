"""Example: well-anchored oracles.

Every expected value is a literal or comes from a source outside the code
under test. Running `oraclecheck examples/healthy_test.py` returns exit 0.
"""

import unittest


class TestArithmeticHealthy(unittest.TestCase):

    def test_add(self):
        self.assertEqual(2 + 3, 5)

    def test_multiply(self):
        # Expected value from a hand-written arithmetic ground truth
        self.assertEqual(6 * 7, 42)

    def test_list_reverse(self):
        # Expected value from a literal ground truth
        self.assertEqual(list(reversed([1, 2, 3])), [3, 2, 1])


if __name__ == "__main__":
    unittest.main()
