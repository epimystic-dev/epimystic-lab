"""Example: state-anchored oracles.

Every assertion below flows an expected value from the code under test
back into the comparison, so a mutation moves both sides together and the
oracle cannot fail.

Running `oraclecheck --sut mymod examples/unhealthy_test.py` returns exit 2.
"""

import unittest


class TestAnchoredOraclesExample(unittest.TestCase):

    def test_self_comparison(self):
        # ORACLE-001: same call on both sides.
        self.assertEqual(mymod.compute(3), mymod.compute(3))

    def test_direct_anchor(self):
        # ORACLE-002: expected assigned from a call to the SUT.
        expected = mymod.compute(3)
        self.assertEqual(mymod.compute(3), expected)

    def test_tautological_roundtrip(self):
        # ORACLE-003: dumps + loads inverse pair on the same input.
        self.assertEqual(mymod.loads(mymod.dumps(payload)), payload)

    def test_snapshot_from_sut(self):
        # ORACLE-004: snapshot captured from the SUT, then compared against
        # another SUT call.
        snap = mymod.render(input_a)
        self.assertEqual(mymod.render(input_b), snap)

    def test_identity(self):
        # ORACLE-005: identity oracle.
        self.assertTrue(handle == handle)

    def test_repr_roundtrip(self):
        # ORACLE-006: repr of same expression on both sides.
        self.assertEqual(repr(obj), repr(obj))

    def test_fixture_from_sut(self):
        # ORACLE-007: expected value defined inside the SUT module.
        self.assertEqual(mymod.compute(3), mymod.EXPECTED_CONSTANT)


if __name__ == "__main__":
    unittest.main()
