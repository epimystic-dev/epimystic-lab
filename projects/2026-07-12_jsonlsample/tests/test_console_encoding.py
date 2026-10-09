"""Sampled records must survive a console that cannot encode them.

jsonlsample's only output is the sampled records themselves, written to
stdout as JSON lines. They were serialised with ensure_ascii=False, so a
record holding a zero-width space or a Cyrillic letter put characters on
stdout that a legacy console cannot encode: on a Windows console (or a pipe)
using code page 1252 the sampler crashed mid-write with a traceback, returned
rc 1, and emitted a truncated sample. Every mode (reservoir, Bernoulli,
stratified) wrote through the same call.

The records are now written with the default ASCII escaping. That is
lossless: a JSON reader recovers the original characters exactly. These
tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the output is pure ASCII, parses back to the original records,
and that the exit code is 0.

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

RECORDS = [
    {"id": 1, "label": "c" + CYRILLIC_A + "t", "text": "p" + ZERO_WIDTH_SPACE + "ay"},
    {"id": 2, "label": "dog", "text": "plain"},
    {"id": 3, "label": "c" + CYRILLIC_A + "t", "text": "x" + CYRILLIC_A},
]


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "jsonlsample"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A UTF-8 JSONL file in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="jls_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "data.jsonl")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            for rec in RECORDS:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _sample(self, *mode, odd_dir=False):
        fx = _Fixture(odd_dir=odd_dir)
        try:
            r = _run_cp1252(fx.path, *mode)
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "sampler crashed:\n" + err)
        self.assertEqual(r.returncode, 0, err)
        # Pure ASCII on stdout, and lossless once parsed.
        lines = r.stdout.decode("ascii").splitlines()
        return [json.loads(line) for line in lines]

    def test_reservoir_sample_is_ascii_and_lossless(self):
        got = self._sample("-n", "3", "--seed", "0")
        self.assertEqual(sorted(got, key=lambda r: r["id"]), RECORDS)

    def test_bernoulli_sample_is_ascii_and_lossless(self):
        got = self._sample("--fraction", "1.0")
        self.assertEqual(got, RECORDS)

    def test_stratified_sample_on_cyrillic_label_is_ascii_and_lossless(self):
        got = self._sample("--stratify", "label", "--per-group", "5")
        self.assertEqual(sorted(got, key=lambda r: r["id"]), RECORDS)

    def test_non_ascii_directory_in_path_is_not_a_crash(self):
        # The input path is not echoed on stdout; the sample must still print.
        got = self._sample("-n", "1", "--seed", "0", odd_dir=True)
        self.assertEqual(len(got), 1)
        self.assertIn(got[0], RECORDS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
