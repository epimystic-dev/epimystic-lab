"""The text report must survive a console that cannot encode what it reports.

The text report echoes the scanned file's path and, inside finding
messages, names and values copied from the delegation config: credential
names, tool names, agent names on a delegation edge, scopes and modes. Any
of those may contain a zero-width space or a Cyrillic letter. The text
reporter used to echo them raw, so on a Windows console using code page
1252 it crashed mid-write with a traceback, returned rc 1, and printed no
finding at all.

These tests force PYTHONIOENCODING=cp1252 so the failure reproduces on any
platform (a Linux CI runner is UTF-8 and would never see it otherwise), and
assert that the finding is printed, that the hidden character is rendered
visibly as <U+XXXX>, and that the exit code reflects the verdict.

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
WEAK = os.path.join(PKG_DIR, "examples", "weak_delegation.json")

ZERO_WIDTH_SPACE = chr(0x200B)
CYRILLIC_A = chr(0x0430)
ODD_DIR = "case" + ZERO_WIDTH_SPACE + CYRILLIC_A


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "delegcheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """The weak example config, mutated, in a fresh temp dir."""

    def __init__(self, mutate=None, odd_dir=False):
        with open(WEAK, encoding="utf-8") as fh:
            doc = json.load(fh)
        if mutate is not None:
            mutate(doc)
        self.root = tempfile.mkdtemp(prefix="dlg_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "delegation.json")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _rename_credential(doc):
    name = "root" + ZERO_WIDTH_SPACE + "_token"
    doc["credentials"][0]["name"] = name
    doc["delegations"][0]["credential_ref"] = name


def _rename_tool(doc):
    doc["tools"][0]["name"] = "sh" + CYRILLIC_A + "ll_exec"


def _newline_in_agent(doc):
    doc["delegations"][0]["to"] = "worker-1\nforged"


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, rule_id, rendered, expect_rc, mutate=None, odd_dir=False):
        fx = _Fixture(mutate, odd_dir=odd_dir)
        try:
            r = _run_cp1252(fx.path)
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "hidden character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out

    def test_zero_width_in_credential_name_is_reported_not_crashed(self):
        # DEL-001 is HIGH, so the verdict is unhealthy and rc 2.
        self._check("DEL-001", "root<U+200B>_token", 2, _rename_credential)

    def test_cyrillic_in_tool_name_is_reported_not_crashed(self):
        self._check("DEL-002", "sh<U+0430>ll_exec", 2, _rename_tool)

    def test_newline_in_agent_name_cannot_forge_a_line(self):
        out = self._check("DEL-005", "worker-1<U+000A>forged", 2,
                          _newline_in_agent)
        for line in out.splitlines():
            self.assertFalse(line.startswith("forged"), line)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check("DEL-001", "<U+200B><U+0430>", 2, odd_dir=True)

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture(_rename_credential, odd_dir=True)
        try:
            r = _run_cp1252(fx.path, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("DEL-001", json.dumps(doc))
        self.assertTrue(any(ZERO_WIDTH_SPACE in f["message"]
                            for f in doc["findings"]))
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
