"""The text report must survive a console that cannot encode what it reports.

approvchainlint echoes input in its text report: the scanned file path, the
property path and message (which carry a tool name), and the snippet line
under each finding (which can carry declared capability names). The text
reporter used to write those raw, so on a Windows console using code page
1252 a zero-width space or a Cyrillic letter in any of them crashed it
mid-write with a traceback, returned rc 1, and printed no finding (or only
part of one). A newline inside a tool name also started a forged line of its
own.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the concealed character is rendered
visibly as <U+XXXX>, and that the exit code reflects the verdict. The summary
and error lines on stderr come from the same text renderer and render the
same way.

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
HEALTHY = os.path.join(PKG_DIR, "examples", "healthy_config.json")

ZERO_WIDTH_SPACE = chr(0x200B)
CYRILLIC_A = chr(0x0430)
NEWLINE = chr(10)
ODD_DIR = "case" + ZERO_WIDTH_SPACE + CYRILLIC_A


def _config(name=None, extra_cap=None):
    """The healthy example; with name set, its read-only tool is mislabeled.

    A tool marked read_only that declares filesystem_write raises AC-007
    (MEDIUM), which echoes the tool name and the capability list.
    """
    with open(HEALTHY, encoding="utf-8") as fh:
        doc = json.load(fh)
    if name is None:
        return doc
    for tool in doc["tools"]:
        if tool["name"] == "read_only_reader":
            tool["name"] = name
            tool["capabilities"] = ["filesystem_write"]
            if extra_cap is not None:
                tool["capabilities"].append(extra_cap)
    return doc


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "approvchainlint"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A config file in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, doc=None, raw=None, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="acl_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "config.json")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            if raw is not None:
                fh.write(raw)
            else:
                json.dump(doc, fh, ensure_ascii=True, indent=2)

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

    def _check(self, fx, rule_id, rendered, expect_rc):
        r, out, err = self._run(fx)
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "concealed character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out, err

    def test_healthy_fixture_is_healthy(self):
        # Guards the fixture builder: the example raises no finding.
        r, out, err = self._run(_Fixture(_config()))
        self.assertEqual(r.returncode, 0, out + err)

    def test_tool_name_echo_is_reported_not_crashed(self):
        # AC-007 is MEDIUM; the name lands in the prop and the message.
        name = "rep" + CYRILLIC_A + "rt" + ZERO_WIDTH_SPACE
        out, _ = self._check(
            _Fixture(_config(name=name)),
            "AC-007", "tools.rep<U+0430>rt<U+200B>.capabilities", 1,
        )
        self.assertNotIn(CYRILLIC_A, out)

    def test_snippet_echo_is_reported_not_crashed(self):
        # The declared capability list lands in the snippet line.
        self._check(
            _Fixture(_config(name="read_only_reader",
                             extra_cap="x" + CYRILLIC_A)),
            "AC-007", "    | ['filesystem_read', 'filesystem_write', 'x<U+0430>']", 1,
        )

    def test_newline_in_tool_name_cannot_forge_a_line(self):
        name = "rep" + NEWLINE + "ort"
        out, _ = self._check(
            _Fixture(_config(name=name)), "AC-007", "tools.rep<U+000A>ort", 1,
        )
        # One finding line plus its snippet line, nothing forged in between.
        self.assertEqual(len(out.splitlines()), 2, out)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            _Fixture(_config(name="read_only_reader"), odd_dir=True),
            "AC-007", "<U+200B><U+0430>", 1,
        )

    def test_error_line_renders_the_same_way(self):
        # A file that is not JSON, in a non-ASCII directory: the error line on
        # stderr names the path and comes from the same text renderer.
        r, out, err = self._run(_Fixture(raw="{ not json", odd_dir=True))
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        errors = [ln for ln in err.splitlines()
                  if ln.startswith("approvchainlint: error: ")]
        self.assertTrue(errors, "no error line; stderr:\n" + err)
        self.assertIn("<U+200B><U+0430>", errors[0])
        self.assertEqual(r.returncode, 2, err)

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        r, out, err = self._run(
            _Fixture(_config(name="rep" + CYRILLIC_A + "rt"), odd_dir=True),
            "--json")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("AC-007", json.dumps(doc))
        self.assertEqual(r.returncode, 1, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
