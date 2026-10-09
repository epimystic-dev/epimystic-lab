"""The text report must survive a console that cannot encode what it reports.

sarifcheck echoes input in its text report: the scanned file path on every
finding line, the property path (which can carry an originalUriBaseIds key),
messages that quote a ruleId, and under --show-matches the matched string
itself. The findings reporter used to write those raw, so on a Windows
console using code page 1252 a zero-width space or a Cyrillic letter in any
of them crashed it mid-write with a traceback, returned rc 1, and printed no
finding at all.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the concealed character is rendered
visibly as <U+XXXX>, and that the exit code reflects the verdict. The summary
block on stderr is built by the same text renderer and renders the same way.

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


def _sarif(uri="src/a.py", rule_id="FX001", base_key="SRCROOT",
           base_uri="file:///build/workspace/"):
    """A small SARIF 2.1.0 log that is healthy with the default arguments."""
    location = {"uri": uri}
    if not uri.startswith("file:"):
        location["uriBaseId"] = "SRCROOT"
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "FixtureScanner",
                "semanticVersion": "1.0.0",
                "rules": [{
                    "id": "FX001",
                    "shortDescription": {"text": "S."},
                    "fullDescription": {"text": "F."},
                    "help": {"text": "H."},
                }],
            }},
            "automationDetails": {"id": "fixture/encoding"},
            "versionControlProvenance": [{
                "repositoryUri": "https://example.invalid/a/b",
                "revisionId": "0" * 40,
            }],
            "originalUriBaseIds": {base_key: {"uri": base_uri}},
            "results": [{
                "ruleId": rule_id,
                "kind": "fail",
                "level": "warning",
                "message": {"text": "Finding."},
                "partialFingerprints": {
                    "primaryLocationLineHash": "1111222233334444:1"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": location,
                    "region": {"startLine": 1},
                }}],
            }],
        }],
    }


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "sarifcheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A SARIF file in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, doc=None, raw=None, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="srf_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "results.sarif")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            if raw is not None:
                fh.write(raw)
            else:
                json.dump(doc, fh, ensure_ascii=True, indent=1)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _run(self, fx, *extra):
        try:
            r = _run_cp1252(fx.path, *extra)
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        return r, out, err

    def _check(self, fx, rule_id, rendered, expect_rc, *extra):
        r, out, err = self._run(fx, *extra)
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "concealed character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out, err

    def test_healthy_fixture_is_healthy(self):
        # Guards the fixture builder: the defaults raise no finding.
        r, out, err = self._run(_Fixture(_sarif()))
        self.assertEqual(r.returncode, 0, out + err)

    def test_show_matches_echo_is_reported_not_crashed(self):
        # SRF-004 is HIGH; --show-matches appends repr(snippet), and repr
        # keeps a printable Cyrillic letter raw.
        doc = _sarif(uri="file:///build/w" + CYRILLIC_A + "rk/a.py")
        out, _ = self._check(
            _Fixture(doc), "SRF-004", "<U+0430>", 2, "--show-matches")
        self.assertIn("match='file:///build/w<U+0430>rk/a.py'", out)

    def test_rule_id_quoted_in_message_is_reported_not_crashed(self):
        # SRF-009 is MEDIUM and quotes the dangling ruleId; rc 1.
        doc = _sarif(rule_id="FX0" + CYRILLIC_A + "1")
        self._check(_Fixture(doc), "SRF-009", "<U+0430>", 1)

    def test_hidden_characters_in_property_path_are_reported_not_crashed(self):
        # The originalUriBaseIds key lands in the property path; SRF-007 is
        # MEDIUM, so the verdict is needs-attention and rc 1.
        doc = _sarif(base_key="SRC" + ZERO_WIDTH_SPACE + CYRILLIC_A,
                     base_uri="file:///home/alice/")
        self._check(_Fixture(doc), "SRF-007", "<U+200B><U+0430>", 1)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        doc = _sarif(uri="file:///build/workspace/src/a.py")
        self._check(_Fixture(doc, odd_dir=True), "SRF-004", "<U+200B><U+0430>", 2)

    def test_summary_error_line_renders_the_same_way(self):
        # A file that is not JSON, in a non-ASCII directory: the summary on
        # stderr names the path and comes from the same text renderer.
        r, out, err = self._run(_Fixture(raw="{ not json", odd_dir=True))
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        named = [ln for ln in err.splitlines() if "case" in ln]
        self.assertTrue(named, "no line names the path; stderr:\n" + err)
        for line in named:
            self.assertIn("<U+200B><U+0430>", line)
        self.assertNotEqual(r.returncode, 0, err)

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        doc = _sarif(uri="file:///build/w" + CYRILLIC_A + "rk/a.py")
        r, out, err = self._run(
            _Fixture(doc, odd_dir=True), "--json", "--show-matches")
        self.assertNotIn("Traceback", err, err)
        parsed = json.loads(r.stdout.decode("ascii"))
        self.assertIn("SRF-004", json.dumps(parsed))
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
