"""The text report must survive a console that cannot encode what it reports.

jwtcheck echoes input back in every text finding: the file path, and in the
message the key name (for example the invalid-identifier parse error,
JWT-P001). A key spelled with a Cyrillic letter that looks Latin, or a file
under a directory whose name holds a zero-width space, puts characters on
stdout that a legacy console cannot encode. The text reporter used to echo
them raw, so on a Windows console using code page 1252 it crashed mid-write
with a traceback, returned rc 1, and printed no finding at all.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the hidden character is rendered
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
        [sys.executable, "-m", "jwtcheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A .env file in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, text, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="jwtc_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "app.env")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _run(self, text, *extra, odd_dir=False):
        fx = _Fixture(text, odd_dir=odd_dir)
        try:
            return _run_cp1252(fx.path, *extra)
        finally:
            fx.close()

    def _check(self, r, rule_id, rendered, expect_rc):
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "hidden character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out

    def test_cyrillic_in_key_is_reported_not_crashed(self):
        # JWT-P001 is an error, so rc 2; the message echoes the key.
        r = self._run("JWT_SECRET" + CYRILLIC_A + "=x\n")
        self._check(r, "JWT-P001", "<U+0430>", 2)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        # JWT-A003 (empty secret) is an error, so rc 2.
        r = self._run("JWT_SECRET=\n", odd_dir=True)
        self._check(r, "JWT-A003", "<U+200B><U+0430>", 2)

    def test_rfc_section_reference_stays_readable(self):
        # The tool's own JWT-A002 message is plain ASCII, so the text report
        # needs no <U+XXXX> rendering for it.
        r = self._run("JWT_ALGORITHM=HS256\nJWT_SECRET=Zq8vR2kT\n")
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        a002 = [ln for ln in out.splitlines() if "JWT-A002" in ln]
        self.assertEqual(len(a002), 1, out)
        self.assertIn("RFC 7518 section 3.2", a002[0])
        self.assertNotIn("<U+", a002[0])
        self.assertEqual(r.returncode, 2, err)

    def test_json_output_was_already_ascii_safe(self):
        # json.dump escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        r = self._run("JWT_SECRET" + CYRILLIC_A + "=x\n", "--json", odd_dir=True)
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("JWT-P001", json.dumps(doc))
        self.assertIn(ODD_DIR, doc[0]["source"])
        self.assertIn("JWT_SECRET" + CYRILLIC_A, doc[0]["message"])
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
