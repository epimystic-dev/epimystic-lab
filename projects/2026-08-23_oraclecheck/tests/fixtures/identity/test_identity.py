"""Fixture: identity oracles + repr round-trips.

Should produce ORACLE-005 (HIGH) and ORACLE-006 (MEDIUM) findings.
"""

import unittest


class TestIdentityOracles(unittest.TestCase):

    def test_bare_identity(self):
        self.assertTrue(obj == obj)  # ORACLE-005 HIGH

    def test_assertIs_same(self):
        self.assertIs(handle.value, handle.value)  # ORACLE-005 HIGH

    def test_repr_roundtrip(self):
        self.assertEqual(repr(model), repr(model))  # ORACLE-006 MEDIUM


if __name__ == "__main__":
    unittest.main()
