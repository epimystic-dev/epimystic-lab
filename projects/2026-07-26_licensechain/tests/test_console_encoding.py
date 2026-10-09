"""The text report must survive a console that cannot encode what it reports.

licensechain echoes the manifest path in its "# licensechain report for"
header and echoes component names (and the upstream they inherit from) on
every finding line. A component name or a directory name containing a
zero-width space or a Cyrillic letter is exactly what a legacy console
cannot encode. The text reporter used to echo them raw, so on a Windows
console using code page 1252 it crashed mid-write with a traceback, returned
rc 1, and printed no finding at all. A newline inside a component name also
started a forged report line of its own.

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
NEWLINE = chr(10)
ODD_DIR = "case" + ZERO_WIDTH_SPACE + CYRILLIC_A

DATASET = "d" + CYRILLIC_A + "ta"
MODEL = "m" + ZERO_WIDTH_SPACE + "o" + NEWLINE + "del"


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "licensechain"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


def _noassertion_manifest():
    # LIC-009 (error): a NOASSERTION license is not a license.
    return {"version": 1, "chain": [
        {"name": DATASET, "role": "dataset", "license": "NOASSERTION"},
    ]}


def _noncommercial_manifest():
    # LIC-011 (error): a non-commercial dataset feeding a commercial model.
    return {"version": 1, "chain": [
        {"name": DATASET, "role": "dataset", "license": "CC-BY-NC-4.0",
         "preserves_notices": True},
        {"name": MODEL, "role": "model", "license": "Apache-2.0",
         "trained_on": [DATASET], "commercial_use": True},
    ]}


class _Fixture(object):
    """A manifest JSON in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, manifest, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="lch_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "chain.json")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, manifest, rule_id, rendered, expect_rc, odd_dir=False):
        fx = _Fixture(manifest, odd_dir=odd_dir)
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

    def test_component_names_are_reported_not_crashed(self):
        out = self._check(
            _noncommercial_manifest(), "LIC-011",
            "m<U+200B>o<U+000A>del <- d<U+0430>ta", 2,
        )
        # The newline inside the component name must not start a line.
        for line in out.splitlines():
            self.assertFalse(line.startswith("del"), line)

    def test_cyrillic_component_in_message_is_rendered(self):
        self._check(
            _noassertion_manifest(), "LIC-009",
            "component 'd<U+0430>ta' declares", 2,
        )

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            _noassertion_manifest(), "LIC-009",
            "<U+200B><U+0430>", 2, odd_dir=True,
        )

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture(_noncommercial_manifest(), odd_dir=True)
        try:
            r = _run_cp1252(fx.path, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("LIC-011", json.dumps(doc))
        self.assertIn(ODD_DIR, doc["source"])
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
