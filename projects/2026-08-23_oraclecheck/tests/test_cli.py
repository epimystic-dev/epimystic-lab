"""CLI contract tests."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from oraclecheck.cli import main


class _TempTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oc-cli-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, content):
        p = Path(self.tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return str(p)

    def _run(self, argv, expected_exit=None):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        if expected_exit is not None:
            self.assertEqual(code, expected_exit, msg=f"stdout={out.getvalue()!r} stderr={err.getvalue()!r}")
        return code, out.getvalue(), err.getvalue()


class TestCLI(_TempTree):

    def test_version_exits_zero(self):
        code, out, _ = self._run(["--version"], expected_exit=0)
        self.assertIn("oraclecheck", out)

    def test_missing_path_stderr_exit_2(self):
        code, _, err = self._run([os.path.join(self.tmp, "nope")], expected_exit=2)
        self.assertIn("does not exist", err)

    def test_healthy_dir_exit_0(self):
        self._write("test_foo.py", "def test_a():\n assert 1 == 2 or True\n")  # a bare-ish assert
        # Above triggers ORACLE-010 (assert True or truthy)? No -- `1 == 2 or True` is not literal.
        # Use a truly clean file:
        self._write("test_bar.py", "class T:\n def t(self):\n  self.assertEqual(compute(1), 2)\n")
        os.remove(os.path.join(self.tmp, "test_foo.py"))
        code, out, err = self._run([self.tmp])
        # test_bar.py is clean (no findings) -> healthy exit 0
        self.assertEqual(code, 0, msg=f"out={out!r} err={err!r}")
        self.assertIn("healthy", out)

    def test_unhealthy_dir_exit_2(self):
        self._write("test_foo.py",
                    "class T:\n def t(self):\n  self.assertEqual(f(x), f(x))\n")
        code, out, _ = self._run([self.tmp])
        self.assertEqual(code, 2)
        self.assertIn("unhealthy", out)

    def test_no_files_default_exit_1(self):
        code, out, _ = self._run([self.tmp])
        self.assertEqual(code, 1)
        self.assertIn("unknown", out)

    def test_no_files_strict_exit_2(self):
        code, out, _ = self._run([self.tmp, "--strict"])
        self.assertEqual(code, 2)
        self.assertIn("unknown", out)

    def test_json_output_parseable(self):
        self._write("test_foo.py",
                    "class T:\n def t(self):\n  self.assertEqual(f(x), f(x))\n")
        code, out, _ = self._run([self.tmp, "--json"])
        parsed = json.loads(out)
        self.assertEqual(parsed["verdict"], "unhealthy")
        self.assertEqual(parsed["exit_code"], 2)

    def test_include_info_surfaces_info_findings_in_text(self):
        self._write("test_foo.py",
                    "class T:\n def t(self):\n  self.assertTrue(True)\n")
        code, out, _ = self._run([self.tmp, "--include-info"])
        self.assertIn("ORACLE-010", out)

    def test_default_path_is_cwd(self):
        # Use --sut to disable inference influence
        original = os.getcwd()
        try:
            os.chdir(self.tmp)
            code, _, _ = self._run([], expected_exit=1)  # empty dir -> unknown -> exit 1
        finally:
            os.chdir(original)

    def test_disable_flag_suppresses_a_rule(self):
        self._write("test_foo.py",
                    "class T:\n def t(self):\n  self.assertTrue(True)\n")
        # Default (INFO hidden, not strict) -> healthy exit 0
        code_a, _, _ = self._run([self.tmp])
        self.assertEqual(code_a, 0)
        # --include-info + --strict would escalate to needs-attention (exit 1)
        code_b, _, _ = self._run([self.tmp, "--include-info", "--strict"])
        self.assertEqual(code_b, 1)
        # ... unless we disable the rule
        code_c, _, _ = self._run([self.tmp, "--include-info", "--strict", "--disable", "ORACLE-010"])
        self.assertEqual(code_c, 0)

    def test_max_files_negative_exit_2(self):
        code, _, err = self._run([self.tmp, "--max-files", "0"], expected_exit=2)
        self.assertIn("positive", err)

    def test_single_file_path(self):
        p = self._write("test_x.py",
                        "class T:\n def t(self):\n  self.assertEqual(f(1), f(1))\n")
        code, out, _ = self._run([p])
        self.assertEqual(code, 2)
        self.assertIn("ORACLE-001", out)

    def test_sut_flag_enables_002(self):
        self._write("helpers.py",
                    "class T:\n def t(self):\n  expected = target.compute(1)\n"
                    "  self.assertEqual(target.compute(1), expected)\n")
        # 'helpers.py' won't be discovered by default globs, so pass as single-file.
        p = os.path.join(self.tmp, "helpers.py")
        code, out, _ = self._run([p, "--sut", "target"])
        self.assertEqual(code, 2)
        self.assertIn("ORACLE-002", out)


if __name__ == "__main__":
    unittest.main()
