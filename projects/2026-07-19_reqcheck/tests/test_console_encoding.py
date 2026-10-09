"""The text report must survive a console that cannot encode what it reports.

reqcheck echoes the requirements file path and the package name as written
(in the finding message and in the suggestion line). REQ-A007 exists to flag
a package name containing a non-ASCII letter such as a Cyrillic a, which is
exactly the kind of character a legacy console cannot encode. The text
reporter used to echo it raw, so on a Windows console using code page 1252 it
crashed mid-write with a traceback, returned rc 1, and printed no finding at
all. A file path with a non-ASCII directory name crashed it the same way.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the concealed character is rendered
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


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "reqcheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A requirements.txt in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, text, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="rqc_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "requirements.txt")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, text, rule_id, rendered, expect_rc, odd_dir=False):
        fx = _Fixture(text, odd_dir=odd_dir)
        try:
            r = _run_cp1252(fx.path)
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "concealed character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out

    def test_cyrillic_package_name_is_reported_not_crashed(self):
        # REQ-A007 (and REQ-A003) are warnings, so rc 1.
        self._check(
            "req" + CYRILLIC_A + "ests==1.0\n",
            "REQ-A007", "'req<U+0430>ests'", 1,
        )

    def test_cyrillic_name_in_suggestion_is_rendered(self):
        # The REQ-A001 suggestion echoes the name as written.
        out = self._check(
            "fl" + CYRILLIC_A + "sk>=1.0\n",
            "REQ-A001", "e.g. 'fl<U+0430>sk==<exact-version>'", 1,
        )
        self.assertIn("REQ-A007", out)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            "requsts==1.0\n",
            "REQ-A003", "<U+200B><U+0430>", 1, odd_dir=True,
        )

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture("req" + CYRILLIC_A + "ests==1.0\n", odd_dir=True)
        try:
            r = _run_cp1252(fx.path, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("REQ-A007", json.dumps(doc))
        self.assertIn(CYRILLIC_A, json.dumps(doc, ensure_ascii=False))
        self.assertEqual(r.returncode, 1, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
