"""Subprocess coverage of the real ``python -m mcptoolcheck`` path.

The in-process ``cli.main`` tests catch everything the module exports;
the subprocess run catches regressions in __main__.py wiring, exit
codes propagated through the real interpreter, and the shared-contract
guarantee that ``python -m <tool>`` resolves to a working CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests.support import (
    build_doc,
    build_tool,
    tag_char,
    write_temp,
)


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args: str):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "mcptoolcheck", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class SubprocessInvocationTests(unittest.TestCase):
    def test_help_returns_zero(self):
        r = _run("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("mcptoolcheck", r.stdout)

    def test_clean_file_returns_zero(self):
        _d, p = write_temp(build_doc([build_tool()]))
        r = _run(p)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("healthy", r.stdout)

    def test_dirty_file_returns_two(self):
        _d, p = write_temp(build_doc([build_tool(
            description="hello" + tag_char() + " world and beyond"
        )]))
        r = _run(p)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("MTC-001", r.stdout)

    def test_json_mode(self):
        _d, p = write_temp(build_doc([build_tool()]))
        r = _run(p, "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["verdict"], "healthy")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
