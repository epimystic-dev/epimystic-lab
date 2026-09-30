import json
import os
import shutil
import tempfile
import unittest

from approvchainlint.scanner import DEFAULT_CANDIDATES, discover, scan_file, scan_paths
from approvchainlint.types import Options

from tests import support  # noqa: F401


class TestDiscover(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="approvchainlint_disc_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _touch(self, rel: str, body: str = "{}"):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
        return p

    def test_direct_file_kept(self):
        p = self._touch("mytools.json")
        got = discover([p], max_files=10)
        self.assertEqual(got, [p])

    def test_directory_walk_finds_settings_json(self):
        self._touch("settings.json")
        self._touch("nested/mcp.json")
        self._touch("nested/README.md")
        got = discover([self.tmp], max_files=10)
        joined = "\n".join(got)
        self.assertIn("settings.json", joined)
        self.assertIn("mcp.json", joined)
        self.assertGreaterEqual(len(got), 2)

    def test_deterministic_sort(self):
        self._touch("b/settings.json")
        self._touch("a/settings.json")
        got1 = discover([self.tmp], max_files=10)
        got2 = discover([self.tmp], max_files=10)
        self.assertEqual(got1, got2)
        self.assertEqual(got1, sorted(got1))

    def test_max_files_cap(self):
        for i in range(5):
            self._touch(f"p{i}/settings.json")
        got = discover([self.tmp], max_files=2)
        self.assertEqual(len(got), 2)

    def test_missing_path_ignored(self):
        got = discover([os.path.join(self.tmp, "no-such")], max_files=10)
        self.assertEqual(got, [])

    def test_default_candidates_constant(self):
        for name in ("settings.json", "mcp.json", ".mcp.json",
                     "tools.json", "agent-tools.json", "permissions.json"):
            self.assertIn(name, DEFAULT_CANDIDATES)

    def test_unrelated_files_skipped(self):
        self._touch("package.json")
        self._touch("README.md")
        got = discover([self.tmp], max_files=10)
        self.assertEqual(got, [])


class TestScanFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="approvchainlint_sf_")
        self.p = os.path.join(self.tmp, "settings.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, obj):
        with open(self.p, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)

    def test_healthy_zero_findings(self):
        self._write({"permissions": {"allow": ["Bash(git status)"]}})
        fs, errs = scan_file(self.p, Options())
        self.assertEqual(errs, [])
        self.assertEqual(fs, [])

    def test_invalid_json_reports_error(self):
        with open(self.p, "w", encoding="utf-8") as f:
            f.write("{not-json")
        fs, errs = scan_file(self.p, Options())
        self.assertEqual(fs, [])
        self.assertEqual(len(errs), 1)
        self.assertIn("json decode error", errs[0])

    def test_missing_file_error(self):
        fs, errs = scan_file(os.path.join(self.tmp, "gone.json"), Options())
        self.assertEqual(len(errs), 1)
        self.assertIn("cannot read", errs[0])
        self.assertEqual(fs, [])

    def test_unhealthy_wildcard(self):
        self._write({"permissions": {"allow": ["Bash(*)"]}})
        fs, errs = scan_file(self.p, Options())
        self.assertEqual(errs, [])
        self.assertTrue(any(f.rule_id == "AC-001" for f in fs))

    def test_disabled_rule_hides_finding(self):
        self._write({"permissions": {"allow": ["Bash(*)"]}})
        fs, _errs = scan_file(self.p, Options(disabled=frozenset({"AC-001"})))
        self.assertFalse(any(f.rule_id == "AC-001" for f in fs))


class TestScanPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="approvchainlint_sp_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_path_zero_files(self):
        r = scan_paths([self.tmp], Options())
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.findings, ())

    def test_findings_sorted_across_files(self):
        pa = os.path.join(self.tmp, "a", "settings.json")
        pb = os.path.join(self.tmp, "b", "settings.json")
        for d in [pa, pb]:
            os.makedirs(os.path.dirname(d), exist_ok=True)
            with open(d, "w", encoding="utf-8") as f:
                json.dump({"permissions": {"allow": ["Bash(*)"]}}, f)
        r = scan_paths([self.tmp], Options())
        self.assertEqual(r.files_scanned, 2)
        paths = [f.path for f in r.findings]
        self.assertEqual(paths, sorted(paths))

    def test_scan_paths_no_args(self):
        r = scan_paths([], Options())
        self.assertEqual(r.files_scanned, 0)


if __name__ == "__main__":
    unittest.main()
