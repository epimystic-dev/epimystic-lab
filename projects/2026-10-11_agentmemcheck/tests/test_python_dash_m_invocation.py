"""`python -m agentmemcheck` subprocess entry test.

The lab's shared CI contract runs each tool via `python -m <name>` so
the subprocess-level entry point must stay wired.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest

from tests import support
from tests.support import (
    build_entry, build_store, tag_char, write_temp,
)


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "agentmemcheck", *args],
        capture_output=True, text=True, env=env, timeout=30,
    )


class DashMInvocationTests(unittest.TestCase):
    def test_help_rc_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("agentmemcheck", r.stdout)

    def test_version_rc_zero(self):
        r = _run("--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.strip().startswith("agentmemcheck "))

    def test_clean_file_rc_zero(self):
        d, p = write_temp(build_store([build_entry()]))
        try:
            r = _run(p)
            self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dirty_file_rc_two(self):
        bad = build_entry(content="hi " + tag_char() + " there")
        d, p = write_temp(build_store([bad]))
        try:
            r = _run(p)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("AMC-001", r.stdout)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
