"""The text report must survive a console that cannot encode what it reports.

pjhookcheck echoes input in its text report: the scanned file path, the
property path and message (which carry a dependency name), and the snippet
line under each finding. The text reporter used to write those raw, so on a
Windows console using code page 1252 a zero-width space or a Cyrillic letter
in any of them crashed it mid-write with a traceback, returned rc 1, and
printed no finding at all. A newline inside a dependency name also started a
forged line of its own.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the concealed character is rendered
visibly as <U+XXXX>, and that the exit code reflects the verdict. The summary
and error lines on stderr come from the same text renderer and render the
same way.

Fixtures are deliberately benign (a "*" version spec, a bundled dependency
list): no install-hook body is needed to reach the echo paths.

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


def _package(deps=None, bundled=None):
    doc = {
        "name": "demo",
        "version": "1.0.0",
        "license": "MIT",
        "packageManager": "pnpm@9.1.4",
        "scripts": {"build": "tsc -p tsconfig.json"},
        "dependencies": deps if deps is not None else {"left-pad": "1.3.0"},
    }
    if bundled is not None:
        doc["bundleDependencies"] = bundled
    return doc


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "pjhookcheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A package.json in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, doc=None, raw=None, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="pjh_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "package.json")
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
        # Guards the fixture builder: the defaults raise no finding.
        r, out, err = self._run(_Fixture(_package()))
        self.assertEqual(r.returncode, 0, out + err)

    def test_dependency_name_echo_is_reported_not_crashed(self):
        # PJH-009 is MEDIUM; the name lands in the prop and the message.
        name = "left-p" + CYRILLIC_A + "d" + ZERO_WIDTH_SPACE
        out, _ = self._check(
            _Fixture(_package(deps={name: "*"})),
            "PJH-009", "left-p<U+0430>d<U+200B>", 1,
        )
        self.assertNotIn(CYRILLIC_A, out)

    def test_snippet_echo_is_reported_not_crashed(self):
        # PJH-010 is MEDIUM; the bundled names land in the snippet line.
        name = "left-p" + CYRILLIC_A + "d" + ZERO_WIDTH_SPACE
        out, _ = self._check(
            _Fixture(_package(bundled=[name])),
            "PJH-010", "    | left-p<U+0430>d<U+200B>", 1,
        )

    def test_newline_in_name_cannot_forge_a_line(self):
        name = "left" + NEWLINE + "pad"
        out, _ = self._check(
            _Fixture(_package(deps={name: "*"})), "PJH-009", "left<U+000A>pad", 1,
        )
        # One finding line plus its snippet line, nothing forged in between.
        self.assertEqual(len(out.splitlines()), 2, out)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check(
            _Fixture(_package(deps={"left-pad": "*"}), odd_dir=True),
            "PJH-009", "<U+200B><U+0430>", 1,
        )

    def test_error_line_renders_the_same_way(self):
        # A file that is not JSON, in a non-ASCII directory: the error line on
        # stderr names the path and comes from the same text renderer.
        r, out, err = self._run(_Fixture(raw="{ not json", odd_dir=True))
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        errors = [ln for ln in err.splitlines() if ln.startswith("pjhookcheck: error: ")]
        self.assertTrue(errors, "no error line; stderr:\n" + err)
        self.assertIn("<U+200B><U+0430>", errors[0])
        self.assertEqual(r.returncode, 2, err)

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        name = "left-p" + CYRILLIC_A + "d"
        r, out, err = self._run(
            _Fixture(_package(deps={name: "*"}), odd_dir=True), "--json")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("PJH-009", json.dumps(doc))
        self.assertEqual(r.returncode, 1, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
