"""The text report must survive a console that cannot encode what it reports.

The findings this tool raises are made of characters a legacy console cannot
encode: a zero-width space in a tool name (MTC-011), a Cyrillic letter inside
a Latin word (MTC-010). The text reporter used to echo those characters raw,
so on a Windows console using code page 1252 it crashed mid-write with a
traceback, returned rc 1, and printed no finding at all - the most dangerous
inputs produced the least output.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the concealed character is rendered
visibly as <U+XXXX>, and that the exit code reflects the finding.

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
HEALTHY = os.path.join(PKG_DIR, "examples", "healthy_tooldesc.json")

ZERO_WIDTH_SPACE = chr(0x200B)
CYRILLIC_A = chr(0x0430)


def _run_cp1252(path, *extra):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "mcptoolcheck", path, *extra],
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    def __init__(self, mutate):
        with open(HEALTHY, encoding="utf-8") as fh:
            doc = json.load(fh)
        tool = dict(doc["tools"][0])
        mutate(tool)
        doc["tools"] = [tool]
        self.dir = tempfile.mkdtemp(prefix="mtc_enc_")
        self.path = os.path.join(self.dir, "tools.json")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=True, indent=2)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, mutate, rule_id, rendered, expect_rc):
        fx = _Fixture(mutate)
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

    def test_zero_width_in_tool_name_is_reported_not_crashed(self):
        # MTC-011 is HIGH, so the verdict is unhealthy and the exit code 2.
        self._check(
            lambda t: t.update(name="read" + ZERO_WIDTH_SPACE + "_file"),
            "MTC-011", "<U+200B>", 2,
        )

    def test_homoglyph_word_is_reported_not_crashed(self):
        # MTC-010 is MEDIUM, so the verdict is needs-attention and rc 1.
        self._check(
            lambda t: t.update(description=(
                "Look up a p" + CYRILLIC_A + "yp" + CYRILLIC_A + "l invoice "
                "by id and return its fields as structured JSON.")),
            "MTC-010", "<U+0430>", 1,
        )

    def test_json_output_was_already_ascii_safe(self):
        # json.dump escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture(lambda t: t.update(name="read" + ZERO_WIDTH_SPACE + "_file"))
        try:
            r = _run_cp1252(fx.path, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("MTC-011", json.dumps(doc))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
