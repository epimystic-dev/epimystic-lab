import json
import os
import shutil
import tempfile
import unittest

from tests.support import fixture_path, run_cli


HEALTHY = fixture_path("healthy_config.json")
WEAK = fixture_path("weak_config.json")


class TestCliBasics(unittest.TestCase):
    def test_version(self):
        rc, out, _err = run_cli(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("approvchainlint", out)

    def test_list_rules(self):
        rc, out, _err = run_cli(["--list-rules"])
        self.assertEqual(rc, 0)
        for i in range(1, 13):
            self.assertIn(f"AC-{i:03d}", out)

    def test_no_paths(self):
        rc, _out, err = run_cli([])
        self.assertEqual(rc, 2)
        self.assertIn("no paths", err)

    def test_unknown_disable(self):
        rc, _out, err = run_cli(["--disable", "AC-999", HEALTHY])
        self.assertEqual(rc, 2)
        self.assertIn("unknown rule", err)

    def test_help_contains_program_name(self):
        # argparse writes help to sys.stdout directly and raises
        # SystemExit(0). We capture sys.stdout with contextlib.
        import contextlib
        import io
        from approvchainlint.cli import main
        buf = io.StringIO()
        rc = None
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            try:
                rc = main(["--help"])
            except SystemExit as e:
                rc = e.code
        self.assertEqual(rc, 0)
        self.assertIn("approvchainlint", buf.getvalue())


class TestCliVerdicts(unittest.TestCase):
    def test_healthy_zero(self):
        rc, out, err = run_cli([HEALTHY])
        self.assertEqual(rc, 0)
        self.assertIn("verdict=healthy", err)
        self.assertNotIn("AC-", out)

    def test_weak_unhealthy(self):
        rc, out, err = run_cli([WEAK])
        self.assertEqual(rc, 2)
        self.assertIn("verdict=unhealthy", err)
        self.assertIn("AC-001", out)

    def test_disable_flips_verdict(self):
        # Disable all HIGH rules; verdict collapses to needs-attention.
        rc, _out, err = run_cli([
            "--disable", "AC-001", "--disable", "AC-002",
            "--disable", "AC-003", "--disable", "AC-004",
            "--disable", "AC-005", WEAK,
        ])
        self.assertEqual(rc, 1)
        self.assertIn("verdict=needs-attention", err)

    def test_json_output(self):
        rc, out, _err = run_cli(["--json", WEAK])
        self.assertEqual(rc, 2)
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "approvchainlint")
        self.assertEqual(doc["verdict"], "unhealthy")
        self.assertGreater(len(doc["findings"]), 0)

    def test_include_info_shows_ac_012(self):
        rc, out, _err = run_cli(["--include-info", WEAK])
        self.assertEqual(rc, 2)
        self.assertIn("AC-012", out)

    def test_info_hidden_by_default(self):
        rc, out, _err = run_cli([WEAK])
        self.assertEqual(rc, 2)
        self.assertNotIn("AC-012", out)


class TestCliDirWalk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="approvchainlint_dir_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, body: str):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)

    def test_walks_directory(self):
        self._write("settings.json", json.dumps(
            {"permissions": {"allow": ["Bash(git status)"]}}
        ))
        self._write("nested/mcp.json", json.dumps(
            {"permissions": {"allow": ["Bash(*)"]}}
        ))
        rc, out, err = run_cli([self.tmp])
        self.assertEqual(rc, 2)
        self.assertIn("AC-001", out)
        self.assertIn("files=2", err)

    def test_strict_no_files_is_unhealthy(self):
        empty = tempfile.mkdtemp(prefix="approvchainlint_empty_")
        try:
            rc, _out, err = run_cli(["--strict", empty])
            self.assertEqual(rc, 2)
        finally:
            shutil.rmtree(empty, ignore_errors=True)

    def test_max_files_zero(self):
        self._write("settings.json", "{}")
        rc, _out, err = run_cli(["--max-files", "0", self.tmp])
        # No files scanned -> unknown -> rc 0
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
