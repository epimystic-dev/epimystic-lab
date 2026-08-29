"""Fixture: mock-echoes-input.

Should produce ORACLE-008 (MEDIUM).
"""

import unittest


class TestMockEcho(unittest.TestCase):

    def test_mock_attr(self):
        m = MagicMock()
        m.return_value = 'sentinel'
        self.assertEqual(m(), 'sentinel')  # ORACLE-008 MEDIUM


if __name__ == "__main__":
    unittest.main()
