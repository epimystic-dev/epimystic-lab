"""Fixture: anchored oracles that should trigger HIGH-severity rules.

Filename `test_target.py` -> SUT inferred as `target`.
"""

import unittest


class TestAnchoredOracles(unittest.TestCase):

    def test_direct_anchor(self):
        expected = target.compute(1)  # ORACLE-002 HIGH
        self.assertEqual(target.compute(1), expected)

    def test_snapshot_from_sut(self):
        snap = target.render(payload_a)  # ORACLE-004 HIGH
        self.assertEqual(target.render(payload_b), snap)

    def test_self_comparison(self):
        self.assertEqual(func(x), func(x))  # ORACLE-001 HIGH

    def test_roundtrip_on_self(self):
        self.assertEqual(target.loads(target.dumps(payload)), payload)  # ORACLE-003 MEDIUM


if __name__ == "__main__":
    unittest.main()
