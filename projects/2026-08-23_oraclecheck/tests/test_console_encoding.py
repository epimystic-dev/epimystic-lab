"""The text report must survive a console that cannot encode what it reports.

The text report echoes the scanned file's path, the identifiers a finding
names (an expected-value variable, a SUT module inferred from the file
name), and per-file error lines made of a path plus an error message. Python
identifiers may legally contain a Cyrillic letter, and a directory name may
contain a zero-width space. The text reporter used to echo those characters
raw, so on a Windows console using code page 1252 it crashed mid-write with
a traceback, returned rc 1, and printed no finding at all.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the hidden character is rendered
visibly as <U+XXXX>, and that the exit code reflects the verdict.

Every special character is built with chr(): no escape sequence appears in
this file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ZERO_WIDTH_SPACE = chr(0x200B)
CYRILLIC_A = chr(0x0430)
ODD_DIR = "case" + ZERO_WIDTH_SPACE + CYRILLIC_A

SELF_COMPARISON = (
    "import unittest\n\n\n"
    "class T(unittest.TestCase):\n"
    "    def test_a(self):\n"
    "        self.assertEqual(func(x), func(x))\n"
)


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "oraclecheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """Test files in a fresh temp dir; a name may start with ODD_DIR."""

    def __init__(self, files):
        self.root = tempfile.mkdtemp(prefix="oc_enc_")
        for rel, text in files.items():
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, files, rule_id, rendered, expect_rc, *extra):
        fx = _Fixture(files)
        try:
            r = _run_cp1252(fx.root, *extra)
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "hidden character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out

    def test_cyrillic_identifier_in_message_is_reported_not_crashed(self):
        # ORACLE-002 is HIGH and names the expected-value variable, so the
        # verdict is unhealthy and rc 2.
        name = "v" + CYRILLIC_A + "l"
        self._check(
            {"test_target.py": (
                "import unittest\n\n\n"
                "class T(unittest.TestCase):\n"
                "    def test_a(self):\n"
                "        " + name + " = target.compute(1)\n"
                "        self.assertEqual(target.compute(1), " + name + ")\n"
            )},
            "ORACLE-002", "v<U+0430>l", 2,
        )

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            {os.path.join(ODD_DIR, "test_target.py"): SELF_COMPARISON},
            "ORACLE-001", "<U+200B><U+0430>", 2,
        )

    def test_error_line_with_non_ascii_path_is_reported_not_crashed(self):
        # A file that does not parse yields an error line echoing its path;
        # a second file with a HIGH finding keeps rc at 2 so the report is
        # written to stdout.
        out = self._check(
            {
                "test_target.py": SELF_COMPARISON,
                os.path.join(ODD_DIR, "test_broken.py"): "def (:\n",
            },
            "ORACLE-001", "<U+200B><U+0430>", 2,
        )
        self.assertIn("ERROR", out)

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture({os.path.join(ODD_DIR, "test_target.py"): SELF_COMPARISON})
        try:
            r = _run_cp1252(fx.root, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("ORACLE-001", json.dumps(doc))
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
