"""Regression lock for envcheck's hostile-input handling.

envcheck was probed 2026-07-28 with 13 hostile inputs and produced zero
tracebacks: every input surfaced as either a structured diagnostic code
or a clean CLI stderr line + non-zero exit code. This file locks that
behaviour in place so a future refactor cannot silently regress the
guards.

Each test corresponds to one probed hostile input. If a refactor drops
a guard (e.g. removes the ``UnicodeDecodeError`` catch in ``parse_bytes``
or the ``OSError`` catch in the CLI), the corresponding test raises the
now-uncaught exception and unittest reports it as a failure.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from envcheck.cli import main
from envcheck.core import parse_bytes


class HostileParseInput(unittest.TestCase):
    """``parse_bytes`` must convert every documented hostile byte payload
    into a structured diagnostic (or accept it cleanly), never a
    traceback."""

    def _codes(self, data: bytes) -> list[str]:
        return [d.code for d in parse_bytes(data).diagnostics]

    def test_empty_file_is_clean(self):
        r = parse_bytes(b"")
        self.assertEqual(r.diagnostics, [])
        self.assertEqual(r.entries, [])

    def test_whitespace_only_is_clean(self):
        r = parse_bytes(b"   \n\t\n  \n")
        self.assertEqual(r.diagnostics, [])
        self.assertEqual(r.entries, [])

    def test_bom_only_emits_e008(self):
        # Regression: dropping the BOM branch would leave this silent.
        self.assertEqual(self._codes(b"\xef\xbb\xbf"), ["E008"])

    def test_crlf_endings_emit_e007(self):
        # Regression: dropping the CRLF branch would leave this silent.
        codes = self._codes(b"A=1\r\nB=2\r\n")
        self.assertIn("E007", codes)

    def test_invalid_utf8_mid_file_emits_e009_not_traceback(self):
        # Regression: dropping the UnicodeDecodeError catch in parse_bytes
        # would let this raise instead of producing E009.
        codes = self._codes(b"A=1\nB=\xff\xfe\xfd\nC=3\n")
        self.assertIn("E009", codes)

    def test_all_nul_bytes_no_traceback(self):
        # NUL bytes are valid UTF-8 but do not form a KEY=VALUE line.
        # Must not crash; must surface as a parse diagnostic.
        r = parse_bytes(b"\x00" * 32)
        self.assertIn("E001", [d.code for d in r.diagnostics])

    def test_random_binary_no_traceback(self):
        # bytes(range(256)) contains invalid UTF-8 leading bytes plus
        # embedded 0x0A newline splitters. Must degrade to E009 + line
        # diagnostics, not raise.
        codes = self._codes(bytes(range(256)))
        self.assertIn("E009", codes)

    def test_huge_single_line_value_accepted(self):
        # A 1 MB single-line value must parse without crashing or losing
        # bytes. Regression guard against any future size cap or
        # streaming rewrite that truncates silently.
        r = parse_bytes(b"A=" + b"x" * 1_000_000 + b"\n")
        self.assertEqual(r.diagnostics, [])
        self.assertEqual(len(r.entries), 1)
        self.assertEqual(r.entries[0][0], "A")
        self.assertEqual(len(r.entries[0][1]), 1_000_000)

    def test_line_without_equals_emits_e001(self):
        codes = self._codes(b"JUST_A_KEY\nA=1\n")
        self.assertIn("E001", codes)

    def test_empty_key_emits_e002(self):
        codes = self._codes(b"=value\nA=1\n")
        self.assertIn("E002", codes)

    def test_bad_shape_key_emits_e003(self):
        codes = self._codes(b"1BAD=x\nA=1\n")
        self.assertIn("E003", codes)

    def test_unclosed_double_quote_emits_e006(self):
        codes = self._codes(b'A="unterminated\n')
        self.assertIn("E006", codes)


class HostileCliInput(unittest.TestCase):
    """The CLI must convert I/O-boundary hostile inputs to a clean
    stderr line + non-zero exit code, never a traceback."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="envcheck_hostile_"))
        self.cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_directory_as_template_returns_two_clean(self):
        # Regression: opening a directory as a template file must not
        # leak an OSError traceback. Windows raises PermissionError,
        # POSIX raises IsADirectoryError; both are OSError and both
        # must be caught by the CLI boundary.
        d = self.tmp / "notafile"
        d.mkdir()
        buf_err = io.StringIO()
        with redirect_stderr(buf_err), redirect_stdout(io.StringIO()):
            rc = main([str(d)])
        self.assertEqual(rc, 2)
        # OS-level Errno text is platform-specific; assert only the
        # stable envcheck-authored prefix.
        self.assertIn("cannot read template", buf_err.getvalue())

    def test_directory_as_env_returns_two_clean(self):
        # Sister guard: same OSError-boundary discipline for the env
        # argument. Distinct code path from the template case.
        (self.tmp / ".env.example").write_text("A=1\n", encoding="utf-8")
        d = self.tmp / "envdir"
        d.mkdir()
        buf_err = io.StringIO()
        with redirect_stderr(buf_err), redirect_stdout(io.StringIO()):
            rc = main([".env.example", str(d)])
        self.assertEqual(rc, 2)
        self.assertIn("cannot read env", buf_err.getvalue())


if __name__ == "__main__":
    unittest.main()
