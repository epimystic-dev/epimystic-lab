"""The text report must survive a console that cannot encode what it reports.

The text report echoes the scanned file's path and, inside finding
messages, names and values copied from the MCP config: server names, env
keys, commands and args. Any of those may contain a zero-width space or a
Cyrillic letter. The text reporter used to echo them raw, so on a Windows
console using code page 1252 it crashed mid-write with a traceback,
returned rc 1, and printed no finding at all.

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

ZERO_WIDTH_SPACE = chr(0x200B)
CYRILLIC_A = chr(0x0430)
ODD_DIR = "case" + ZERO_WIDTH_SPACE + CYRILLIC_A

# A server with neither command nor url: MSC-005, HIGH, so rc 2.
BROKEN = {"description": "no command, no url"}


def _run_cp1252(*args):
    env = os.environ.copy()
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "cp1252"
    return subprocess.run(
        [sys.executable, "-m", "mcpservercheck"] + list(args),
        capture_output=True, env=env, timeout=30,
    )


class _Fixture(object):
    """An mcp.json with the given servers, in a fresh temp dir."""

    def __init__(self, servers, odd_dir=False):
        self.root = tempfile.mkdtemp(prefix="msc_enc_")
        parent = os.path.join(self.root, ODD_DIR) if odd_dir else self.root
        os.makedirs(parent, exist_ok=True)
        self.path = os.path.join(parent, "mcp.json")
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"mcpServers": servers}, fh, ensure_ascii=False, indent=2)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


class ConsoleEncodingTests(unittest.TestCase):
    def _check(self, servers, rule_id, rendered, expect_rc, *extra, **kw):
        fx = _Fixture(servers, odd_dir=kw.get("odd_dir", False))
        try:
            r = _run_cp1252(fx.path, *extra)
        finally:
            fx.close()
        out = r.stdout.decode("cp1252", errors="replace")
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, "reporter crashed:\n" + err)
        self.assertIn(rule_id, out, "finding not printed; stderr:\n" + err)
        self.assertIn(rendered, out, "hidden character not made visible")
        self.assertEqual(r.returncode, expect_rc, err)
        return out

    def test_zero_width_in_server_name_is_reported_not_crashed(self):
        self._check({"bro" + ZERO_WIDTH_SPACE + "ken": BROKEN},
                    "MSC-005", "bro<U+200B>ken", 2)

    def test_cyrillic_in_env_key_is_reported_not_crashed(self):
        # MSC-007 is MEDIUM; the broken server keeps the verdict at rc 2.
        servers = {
            "broken": BROKEN,
            "cred-env": {
                "command": "/usr/local/bin/server",
                "env": {"DB_PASSWORD_" + CYRILLIC_A: "example-value"},
            },
        }
        self._check(servers, "MSC-007", "DB_PASSWORD_<U+0430>", 2)

    def test_cyrillic_in_command_is_reported_not_crashed(self):
        # MSC-010 is INFO, so it needs --include-info to be shown.
        servers = {
            "broken": BROKEN,
            "bare": {"command": "my-mcp-serv" + CYRILLIC_A + "r"},
        }
        self._check(servers, "MSC-010", "my-mcp-serv<U+0430>r", 2,
                    "--include-info")

    def test_newline_in_server_name_cannot_forge_a_line(self):
        out = self._check({"broken\nforged": BROKEN},
                          "MSC-005", "broken<U+000A>forged", 2)
        for line in out.splitlines():
            self.assertFalse(line.startswith("forged"), line)

    def test_non_ascii_directory_in_path_is_reported_not_crashed(self):
        self._check({"broken": BROKEN}, "MSC-005", "<U+200B><U+0430>", 2,
                    odd_dir=True)

    def test_json_output_was_already_ascii_safe(self):
        # json.dumps escapes to ASCII by default; lock that in so a future
        # ensure_ascii=False cannot reintroduce the crash on this path.
        fx = _Fixture({"bro" + ZERO_WIDTH_SPACE + "ken": BROKEN}, odd_dir=True)
        try:
            r = _run_cp1252(fx.path, "--json")
        finally:
            fx.close()
        err = r.stderr.decode("cp1252", errors="replace")
        self.assertNotIn("Traceback", err, err)
        doc = json.loads(r.stdout.decode("ascii"))
        self.assertIn("MSC-005", json.dumps(doc))
        self.assertTrue(any(ZERO_WIDTH_SPACE in f["message"]
                            for f in doc["findings"]))
        self.assertEqual(r.returncode, 2, err)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
