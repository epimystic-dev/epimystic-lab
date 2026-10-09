"""The text report must survive a console that cannot encode what it reports.

envcheck echoes input back in every diagnostic: the file path, and for the
key checks (E003, E004, D001, D002, D003) the key itself. A key spelled with
a Cyrillic letter that looks Latin, or a file under a directory whose name
holds a zero-width space, puts characters on stdout that a legacy console
cannot encode. The text reporter used to echo them raw, so on a Windows
console using code page 1252 it crashed mid-write with a traceback, returned
rc 1, and printed no diagnostic at all. The JSON reporter used
ensure_ascii=False and crashed the same way.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the diagnostic is printed, that the hidden character is rendered
visibly as <U+XXXX>, and that the exit code reflects the findings.

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


def _run_cp1252(cwd, *args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "envcheck"] + list(args),
        capture_output=True, env=env, timeout=30, cwd=cwd,
    )


class _Fixture(object):
    """A template file in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, text, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="envc_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "template.env")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, text, code, rendered, odd_dir=False):
        fx = _Fixture(text, odd_dir=odd_dir)
        try:
            r = _run_cp1252(fx.root, fx.path, "--no-drift")
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(code, out, "diagnostic not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "hidden character not made visible")
        # Any diagnostic means rc 1.
        self.assertEqual(r.returncode, 1, err)

    def test_cyrillic_in_key_is_reported_not_crashed(self):
        # E003: the key is echoed in the message, Cyrillic letter included.
        self._check("API_KEY" + CYRILLIC_A + "=1\n", "E003", "<U+0430>")

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            "A B=1\n", "E003", "<U+200B><U+0430>", odd_dir=True,
        )

    def test_json_output_is_ascii_safe(self):
        # The JSON lines used ensure_ascii=False and crashed the same way.
        # With the default escaping the output is pure ASCII and lossless:
        # the parsed record holds the original characters.
        key = "API_KEY" + CYRILLIC_A
        fx = _Fixture(key + "=1\n", odd_dir=True)
        try:
            r = _run_cp1252(fx.root, fx.path, "--no-drift", "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        lines = r.stdout.decode("ascii").splitlines()
        self.assertEqual(len(lines), 1, lines)
        record = json.loads(lines[0])
        self.assertEqual(record["code"], "E003")
        self.assertEqual(record["key"], key)
        self.assertIn(ODD_DIR, record["file"])
        self.assertEqual(r.returncode, 1, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
