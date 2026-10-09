"""The text report must survive a console that cannot encode what it reports.

jsonldiff echoes record content back in every change line: the changed
values, the dotted path (built from the records' own key names), and the
alignment key. A value or key name holding a zero-width space or a Cyrillic
letter puts characters on stdout that a legacy console cannot encode. The
text reporter used to echo them raw (its value formatter used
ensure_ascii=False), so on a Windows console using code page 1252 it crashed
mid-write with a traceback, returned rc 1, and printed no difference at all.
The --format json reporter used ensure_ascii=False and crashed the same way.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the difference is printed, that the hidden character is rendered
visibly as <U+XXXX>, and that the exit code is the one the diff calls for.

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
NEWLINE = chr(10)
ODD_DIR = "case" + ZERO_WIDTH_SPACE + CYRILLIC_A


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "jsonldiff"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A baseline/candidate JSONL pair, optionally under a non-ASCII dir."""

    def __init__(self, baseline, candidate, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="jld_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.baseline = self._write(parent, "baseline.jsonl", baseline)
        self.candidate = self._write(parent, "candidate.jsonl", candidate)

    @staticmethod
    def _write(parent, name, records):
        path = os.path.join(parent, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for rec in records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return path

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _run(self, baseline, candidate, *extra, odd_dir=False):
        fx = _Fixture(baseline, candidate, odd_dir=odd_dir)
        try:
            return _run_cp1252(fx.baseline, fx.candidate, *extra)
        finally:
            fx.close()

    def _check(self, r, marker, rendered, expect_rc):
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(marker, out, "difference not printed; stderr:\n" + err)
        if rendered:
            self.assertIn(rendered, out, "hidden character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out

    def test_zero_width_in_changed_value_is_reported_not_crashed(self):
        r = self._run(
            [{"id": "a", "name": "pay"}],
            [{"id": "a", "name": "p" + ZERO_WIDTH_SPACE + "ay"}],
            "--exit-code",
        )
        self._check(r, "name:", "<U+200B>", 1)

    def test_cyrillic_in_key_name_is_reported_not_crashed(self):
        # The added path is the record's own key name, Cyrillic letter included.
        r = self._run(
            [{"id": "a"}],
            [{"id": "a", "n" + CYRILLIC_A + "me": 1}],
            "--exit-code",
        )
        self._check(r, "+ n", "<U+0430>", 1)

    def test_cyrillic_in_alignment_key_is_reported_not_crashed(self):
        # A duplicate alignment key is a parse error (rc 2) whose message
        # echoes the key value.
        dup = "c" + CYRILLIC_A + "se-01"
        r = self._run(
            [{"id": dup}, {"id": dup}],
            [{"id": dup}],
            "--key", "id",
        )
        self._check(r, "PARSE ERROR", "<U+0430>", 2)

    def test_newline_in_key_name_cannot_forge_a_line(self):
        r = self._run(
            [{"id": "a"}],
            [{"id": "a", "x" + NEWLINE + "  line 9  + forged": 1}],
            "--exit-code",
        )
        out = self._check(r, "+ x", "<U+000A>", 1)
        self.assertEqual(len(out.splitlines()), 1, out)

    def test_non_ascii_directory_in_path_is_not_a_crash(self):
        # Input paths are not echoed in the report; the diff must still print.
        r = self._run(
            [{"id": "a", "score": 1}],
            [{"id": "a", "score": 2}],
            "--exit-code", odd_dir=True,
        )
        self._check(r, "score: 1 -> 2", None, 1)

    def test_json_output_is_ascii_safe(self):
        # The JSON lines used ensure_ascii=False and crashed the same way.
        # With the default escaping the output is pure ASCII and lossless:
        # the parsed change holds the original characters.
        new = "p" + ZERO_WIDTH_SPACE + CYRILLIC_A + "y"
        r = self._run(
            [{"id": "a", "name": "pay"}],
            [{"id": "a", "name": new}],
            "--format", "json", "--exit-code", odd_dir=True,
        )
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        lines = r.stdout.decode("ascii").splitlines()
        self.assertEqual(len(lines), 1, lines)
        change = json.loads(lines[0])
        self.assertEqual(change["kind"], "changed")
        self.assertEqual(change["path"], "name")
        self.assertEqual(change["candidate"], new)
        self.assertEqual(r.returncode, 1, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
