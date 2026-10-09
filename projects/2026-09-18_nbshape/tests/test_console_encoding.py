"""The text report must survive a console that cannot encode what it reports.

nbshape echoes input in its text report: the notebook path on every finding
line, and fragments of the notebook itself in some messages (the path literal
NBK-005 flags, the cell id NBK-017 flags). The findings reporter used to
write those raw, so on a Windows console using code page 1252 a zero-width
space or a Cyrillic letter in a path or a cell crashed it mid-write with a
traceback, returned rc 1, and printed no finding at all.

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

PY_META = {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python", "version": "3.11.4"},
}


def _notebook(source, cid=None):
    cell = {
        "cell_type": "code",
        "execution_count": 1,
        "metadata": {},
        "outputs": [],
        "source": source,
    }
    if cid is not None:
        cell["id"] = cid
    return {
        "cells": [cell],
        "metadata": PY_META,
        "nbformat": 4,
        "nbformat_minor": 5 if cid is not None else 4,
    }


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "nbshape"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """A notebook file in a fresh temp dir, optionally under a non-ASCII dir."""

    def __init__(self, doc=None, raw=None, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="nbs_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "notebook.ipynb")
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

    def _check(self, fx, rule_id, rendered, expect_rc):
        r, out, err = self._run(fx)
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "concealed character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out, err

    def test_cyrillic_in_path_literal_is_reported_not_crashed(self):
        # NBK-005 is HIGH and echoes the path literal; verdict unhealthy, rc 2.
        src = 'x = open("/home/alice/d' + CYRILLIC_A + 'ta.csv")\n'
        self._check(_Fixture(_notebook(src)), "NBK-005", "<U+0430>", 2)

    def test_zero_width_in_path_literal_is_reported_not_crashed(self):
        src = 'x = open("/home/alice/d' + ZERO_WIDTH_SPACE + 'ata.csv")\n'
        self._check(_Fixture(_notebook(src)), "NBK-005", "<U+200B>", 2)

    def test_hidden_characters_in_cell_id_are_reported_not_crashed(self):
        # NBK-017 echoes the malformed cell id; it is the only finding.
        fx = _Fixture(_notebook("x = 1\n", cid="a" + ZERO_WIDTH_SPACE + CYRILLIC_A))
        r, out, err = self._run(fx, "--include-info")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn("NBK-017", out, "finding not printed; stderr:\n" + err)
        self.assertIn("<U+200B><U+0430>", out)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        src = 'x = open("/home/alice/data.csv")\n'
        self._check(
            _Fixture(_notebook(src), odd_dir=True),
            "NBK-005", "<U+200B><U+0430>", 2,
        )

    def test_summary_diagnostic_renders_the_same_way(self):
        # An unparseable file in a non-ASCII directory raises the always-
        # visible NBK-010 gate finding on stdout and a diagnostic line naming
        # the path on stderr; both come from the text renderer.
        r, out, err = self._run(_Fixture(raw="{ not json", odd_dir=True))
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn("NBK-010", out, "finding not printed; stderr:\n" + err)
        self.assertIn("<U+200B><U+0430>", out)
        diag = [ln for ln in err.splitlines() if ln.startswith("diagnostic: ")]
        self.assertTrue(diag, "no diagnostic line; stderr:\n" + err)
        self.assertIn("<U+200B><U+0430>", diag[0])
        self.assertEqual(r.returncode, 1, err)

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        src = 'x = open("/home/alice/d' + CYRILLIC_A + 'ta.csv")\n'
        fx = _Fixture(_notebook(src), odd_dir=True)
        r, out, err = self._run(fx, "--json")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("NBK-005", json.dumps(doc))
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
