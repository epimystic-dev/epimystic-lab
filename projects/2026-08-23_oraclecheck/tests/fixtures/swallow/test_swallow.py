"""Fixture: assertion swallowed inside try-except-pass.

Should produce ORACLE-009 (HIGH).
"""

import unittest


class TestSwallowed(unittest.TestCase):

    def test_assert_swallowed(self):
        try:
            assert compute() == expected  # ORACLE-009 HIGH
        except AssertionError:
            pass

    def test_assertX_swallowed(self):
        try:
            self.assertEqual(a, b)  # ORACLE-009 HIGH
        except AssertionError:
            pass


if __name__ == "__main__":
    unittest.main()
