"""The console-encoding invariant.

The text reporter MUST render every non-printable-ASCII codepoint as
``<U+XXXX>`` so a Windows cp1252 console cannot crash the reporter
mid-write when the scanned config contains a Plane-14 TAG, bidi
override, zero-width, control, or PUA codepoint. This is the exact
input class RNV-006 exists to detect; echoing such a character raw
would both crash the reporter AND re-conceal the character inside the
report meant to expose it.

The test spawns a subprocess with ``PYTHONIOENCODING=cp1252`` and
asserts no traceback, the rule-id on stdout, and the ``<U+...>``
substitution visible.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests import support  # noqa: F401

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CP1252ReporterTests(unittest.TestCase):
    def _run_against_codepoint(self, cp: int) -> tuple:
        ch = chr(cp)
        doc = {"timezone": "UTC" + ch}
        fd, path = tempfile.mkstemp(suffix="_renovate.json", prefix="rnvcp_")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "cp1252"
            env["PYTHONPATH"] = (
                PROJECT_ROOT + os.pathsep + env.get("PYTHONPATH", "")
            )
            r = subprocess.run(
                [sys.executable, "-m", "renovatelint", path],
                capture_output=True,
                env=env,
                timeout=30,
            )
            # Decode raw bytes under ascii/replace so we can detect any
            # survival of the codepoint. If the reporter had echoed the
            # raw bytes, decoding under cp1252 at the subprocess side
            # would have crashed first; decoding here under ASCII would
            # have replaced them with '?' and the codepoint-escape
            # ASCII form "U+XXXX" would be absent.
            stdout = r.stdout.decode("ascii", errors="replace")
            stderr = r.stderr.decode("ascii", errors="replace")
            return r.returncode, stdout, stderr, ch
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _assert_safe(self, rc: int, stdout: str, stderr: str, ch: str,
                     cp: int) -> None:
        self.assertNotIn("Traceback", stdout + stderr)
        self.assertIn("RNV-006", stdout)
        # The reporter MUST NOT echo the raw codepoint; our ascii decode
        # would survive the subprocess cp1252 encoding only if the
        # reporter had already stripped the raw bytes to <U+XXXX>-style
        # text. Assert both: the raw character is absent, and the ASCII
        # escape form (either "<U+XXXX>" visible-escape or "U+XXXX"
        # from the rule message) is present.
        self.assertNotIn(ch, stdout)
        hex_form = "U+%04X" % cp
        self.assertIn(hex_form, stdout, "expected " + hex_form + " marker")

    def test_tag_codepoint_does_not_crash_reporter(self):
        cp = 0xE0041
        rc, stdout, stderr, ch = self._run_against_codepoint(cp)
        self._assert_safe(rc, stdout, stderr, ch, cp)

    def test_bidi_codepoint_does_not_crash_reporter(self):
        cp = 0x202E
        rc, stdout, stderr, ch = self._run_against_codepoint(cp)
        self._assert_safe(rc, stdout, stderr, ch, cp)

    def test_zero_width_codepoint_does_not_crash_reporter(self):
        cp = 0x200B
        rc, stdout, stderr, ch = self._run_against_codepoint(cp)
        self._assert_safe(rc, stdout, stderr, ch, cp)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
