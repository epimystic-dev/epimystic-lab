"""The text report must survive a console that cannot encode what it reports.

aicontribcheck echoes the repository root and policy file paths, and quotes
the matched policy line as evidence under each finding. A policy line or a
directory name containing a zero-width space or a Cyrillic letter is exactly
what a legacy console cannot encode. The text reporter used to echo them
raw, so on a Windows console using code page 1252 it crashed mid-write with
a traceback, returned rc 1, and printed no finding at all.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the concealed character is rendered
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

BAN_LINE = "This project does not accept AI-generated contributions."


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "aicontribcheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A repo with one CONTRIBUTING.md, optionally under a non-ASCII dir."""

    def __init__(self, text, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="acc_enc_")
        self.repo = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(self.repo, exist_ok=True)
        path = os.path.join(self.repo, "CONTRIBUTING.md")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, text, rule_id, rendered, expect_rc, odd_dir=False):
        fx = _Fixture(text, odd_dir=odd_dir)
        try:
            r = _run_cp1252(fx.repo)
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "concealed character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)

    def test_hidden_characters_in_evidence_are_reported_not_crashed(self):
        # AICONTRIB-001 is an explicit ban: verdict banned, rc 2.
        self._check(
            "# Contributing\n\n" + BAN_LINE + " Note" + ZERO_WIDTH_SPACE
            + " p" + CYRILLIC_A + "tch.\n",
            "AICONTRIB-001", "Note<U+200B> p<U+0430>tch.", 2,
        )

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            "# Contributing\n\n" + BAN_LINE + "\n",
            "AICONTRIB-001", "<U+200B><U+0430>", 2, odd_dir=True,
        )

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture(
            "# Contributing\n\n" + BAN_LINE + " Note" + ZERO_WIDTH_SPACE
            + ".\n",
            odd_dir=True,
        )
        try:
            r = _run_cp1252(fx.repo, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("AICONTRIB-001", json.dumps(doc))
        self.assertIn(ODD_DIR, doc["root"])
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
