"""Unreadable input (binary or non-UTF-8 bytes) is a finding with exit 2, never a traceback."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from renovatelint.scanner import scan_file
from renovatelint.types import Options

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = {
    "latin1.json": b'{"enabled": "caf\xe9"}',
    "binary.json": bytes(range(256)) * 4,
}


class UnreadableInput(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="rnv_unreadable_")
        for name, data in CASES.items():
            with open(os.path.join(self.d, name), "wb") as fh:
                fh.write(data)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_scan_file_reports_rnv000(self):
        for name in CASES:
            r = scan_file(os.path.join(self.d, name), Options())
            self.assertEqual([f.rule_id for f in r.findings], ["RNV-000"], name)

    def test_cli_exits_2_without_traceback(self):
        env = dict(os.environ, PYTHONPATH=PROJECT_ROOT)
        for name in CASES:
            p = subprocess.run([sys.executable, "-m", "renovatelint", os.path.join(self.d, name)],
                               capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(p.returncode, 2, name)
            self.assertNotIn("Traceback", p.stdout + p.stderr, name)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
