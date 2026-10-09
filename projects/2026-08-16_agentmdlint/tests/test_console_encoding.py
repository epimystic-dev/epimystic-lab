"""The text report must survive a console that cannot encode what it reports.

agentmdlint echoes the scan root and file path on every finding line, and
quotes heading text in its dead-heading and purpose-heading messages
(AGENTMD-005, AGENTMD-009). A heading or a directory name containing a
zero-width space or a Cyrillic letter is exactly what a legacy console
cannot encode. The text reporter used to echo them raw, so on a Windows
console using code page 1252 it crashed mid-write with a traceback, returned
rc 1, and printed no finding at all.

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

# A drift marker (AGENTMD-006, medium) makes the verdict needs-attention and
# rc 1, so the text report goes to stdout rather than stderr.
BASE = (
    "# Project guide\n\n"
    "## Rules\n\n"
    "You must run the tests before pushing because CI is slow.\n"
    "- TODO: revisit.\n"
)
ODD_HEADING = "Empt" + ZERO_WIDTH_SPACE + "y p" + CYRILLIC_A + "rt"


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "agentmdlint"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """An AGENTS.md in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, text, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="aml_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "AGENTS.md")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, text, rule_id, rendered, expect_rc, odd_dir=False):
        fx = _Fixture(text, odd_dir=odd_dir)
        try:
            r = _run_cp1252(fx.path, "--include-info")
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "concealed character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)

    def test_hidden_characters_in_heading_are_reported_not_crashed(self):
        # AGENTMD-005 quotes the heading text of an empty section.
        self._check(
            BASE + "\n## " + ODD_HEADING + "\n",
            "AGENTMD-005", "heading 'Empt<U+200B>y p<U+0430>rt'", 1,
        )

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            BASE, "AGENTMD-006", "<U+200B><U+0430>", 1, odd_dir=True,
        )

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture(BASE + "\n## " + ODD_HEADING + "\n", odd_dir=True)
        try:
            r = _run_cp1252(fx.path, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("AGENTMD-006", json.dumps(doc))
        self.assertIn(ODD_DIR, doc["root"])
        self.assertIn(ODD_HEADING, json.dumps(doc, ensure_ascii=False))
        self.assertEqual(r.returncode, 1, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
