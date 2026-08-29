"""Fixture: vacuous assertions.

Should produce ORACLE-010 (INFO) findings. Under default settings (INFO hidden,
not strict) the verdict is 'healthy'; under --strict it becomes
'needs-attention'.
"""

import unittest


class TestVacuous(unittest.TestCase):

    def test_placeholder_true(self):
        self.assertTrue(True)  # ORACLE-010 INFO

    def test_placeholder_false(self):
        self.assertFalse(False)  # ORACLE-010 INFO

    def test_bare_truthy(self):
        assert 1  # ORACLE-010 INFO


if __name__ == "__main__":
    unittest.main()
