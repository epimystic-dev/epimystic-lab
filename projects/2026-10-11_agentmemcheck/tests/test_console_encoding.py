"""The reporter must never crash on a console that cannot encode what
it is reporting.

A Windows console using code page 1252 cannot encode a zero-width
space or a Cyrillic letter. The findings this tool exists to raise
are made of exactly those characters. Echoing them raw crashed the
reporter mid-write, so the most dangerous inputs would produce a
traceback and no finding. This test invokes the real CLI as a
subprocess with PYTHONIOENCODING forced to cp1252 and asserts that:

  - no traceback is written to stderr
  - the rule id is printed
  - the hidden character is rendered as <U+XXXX> in the output

The same is checked for --json (which must escape by default too).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest

from tests import support
from tests.support import (
    build_entry, build_store, homoglyph_word, tag_char, write_temp,
)


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_subprocess(path: str, flags, encoding: str = "cp1252"):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = encoding
    return subprocess.run(
        [sys.executable, "-m", "agentmemcheck", *flags, path],
        capture_output=True, text=True, env=env, timeout=30,
        encoding="utf-8", errors="replace",
    )


class ConsoleEncodingTests(unittest.TestCase):
    def _dirty_file(self):
        # Two inputs that would otherwise crash cp1252: a TAG in content
        # (fires AMC-001, which describes the codepoint in ASCII) and a
        # Cyrillic-containing identifier (fires AMC-009, whose message
        # quotes the raw non-ASCII word verbatim and so forces the
        # reporter's _visible path).
        bad = build_entry(
            content="hi " + tag_char() + " there",
            user=homoglyph_word(),
        )
        return write_temp(build_store([bad]))

    def test_text_mode_no_traceback_under_cp1252(self):
        d, p = self._dirty_file()
        try:
            r = _run_subprocess(p, flags=[])
            self.assertNotIn("Traceback", r.stderr)
            self.assertNotIn(
                "UnicodeEncodeError", r.stderr + r.stdout,
            )
            self.assertIn("AMC-001", r.stdout)
            # The raw Cyrillic in the AMC-009 identifier is quoted
            # verbatim into the message; the reporter must render it
            # as <U+0430> rather than echo it raw.
            self.assertIn("<U+0430>", r.stdout)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_json_mode_no_traceback_under_cp1252(self):
        d, p = self._dirty_file()
        try:
            r = _run_subprocess(p, flags=["--json"])
            self.assertNotIn("Traceback", r.stderr)
            # Default ensure_ascii=True means every non-ASCII codepoint
            # is already escaped as \uXXXX before stream encoding.
            parsed = json.loads(r.stdout)
            self.assertEqual(parsed["verdict"], "unhealthy")
            self.assertEqual(
                parsed["findings"][0]["rule_id"], "AMC-001",
            )
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
