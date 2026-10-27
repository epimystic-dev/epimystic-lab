"""Scanner tests for renovatelint.scanner."""

from __future__ import annotations

import json
import os
import unittest

from tests.support import write_temp, write_temp_text

from renovatelint.scanner import discover_paths, scan_file, scan_paths, scan_text
from renovatelint.types import Options, Severity, Verdict


class DiscoverPathsTests(unittest.TestCase):
    def test_file_input_returned_verbatim(self):
        d, p = write_temp({"enabled": True})
        try:
            found = discover_paths(p)
            self.assertEqual(found, [p])
        finally:
            self._cleanup(d)

    def test_directory_walks_standard_names(self):
        d, p = write_temp({"enabled": True})
        try:
            found = discover_paths(d)
            self.assertIn(p, found)
        finally:
            self._cleanup(d)

    def test_nonexistent_path_returns_empty(self):
        found = discover_paths("/no/such/path/__not_here__")
        self.assertEqual(found, [])

    def test_renovaterc_variants_discovered(self):
        _, p = write_temp({"enabled": True}, name=".renovaterc.json")
        d = os.path.dirname(p)
        try:
            found = discover_paths(d)
            self.assertIn(p, found)
        finally:
            self._cleanup(d)

    def _cleanup(self, d):
        import shutil
        shutil.rmtree(d, ignore_errors=True)


class ScanTextTests(unittest.TestCase):
    def test_clean_doc_returns_healthy(self):
        content = json.dumps({
            "$schema": "https://docs.renovatebot.com/renovate-schema.json",
            "timezone": "UTC",
            "extends": ["config:recommended"],
        })
        r = scan_text(content, "renovate.json", Options())
        self.assertEqual(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.files_scanned, 1)
        self.assertEqual(r.findings, [])

    def test_dirty_doc_returns_unhealthy(self):
        content = json.dumps({"enabled": False})
        r = scan_text(content, "renovate.json", Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertTrue(any(f.rule_id == "RNV-001" for f in r.findings))

    def test_parse_error_produces_rnv000_finding(self):
        r = scan_text("{not json", "renovate.json", Options())
        self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        self.assertTrue(any(f.rule_id == "RNV-000" for f in r.findings))
        self.assertEqual(r.findings[0].severity, Severity.HIGH)

    def test_package_json_without_renovate_key_is_skipped(self):
        r = scan_text(
            '{"name": "pkg"}',
            "package.json",
            Options(),
        )
        # files_scanned=0 because the file is not a renovatelint target.
        self.assertEqual(r.files_scanned, 0)
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.findings, [])

    def test_package_json_with_renovate_key_is_scanned(self):
        r = scan_text(
            json.dumps({"name": "pkg", "renovate": {"enabled": False}}),
            "package.json",
            Options(),
        )
        self.assertEqual(r.files_scanned, 1)
        self.assertTrue(any(f.rule_id == "RNV-001" for f in r.findings))


class ScanFileAndScanPathsTests(unittest.TestCase):
    def test_scan_file_reads_and_lints(self):
        d, p = write_temp({"enabled": False})
        try:
            r = scan_file(p, Options())
            self.assertEqual(r.verdict, Verdict.UNHEALTHY)
            self.assertTrue(any(f.rule_id == "RNV-001" for f in r.findings))
        finally:
            self._cleanup(d)

    def test_scan_paths_merges_multiple_files(self):
        d1, p1 = write_temp({"enabled": False})
        d2, p2 = write_temp({"enabled": True, "automerge": True})
        try:
            r = scan_paths([p1, p2], Options())
            self.assertEqual(r.files_scanned, 2)
            ids = {f.rule_id for f in r.findings}
            self.assertIn("RNV-001", ids)
            self.assertIn("RNV-002", ids)
            self.assertEqual(r.verdict, Verdict.UNHEALTHY)
        finally:
            self._cleanup(d1)
            self._cleanup(d2)

    def test_scan_paths_unreadable_file_surfaces_rnv000(self):
        r = scan_file("D:/no_such_renovate_config_12345.json", Options())
        self.assertTrue(any(f.rule_id == "RNV-000" for f in r.findings))

    def test_scan_paths_empty_input_returns_unknown(self):
        r = scan_paths([], Options())
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.files_scanned, 0)

    def _cleanup(self, d):
        import shutil
        shutil.rmtree(d, ignore_errors=True)


class JSONCFileScanTests(unittest.TestCase):
    def test_jsonc_file_with_comments_scans_cleanly(self):
        text = (
            '{\n'
            '  // keep this comment\n'
            '  "$schema": "https://docs.renovatebot.com/renovate-schema.json",\n'
            '  "timezone": "UTC",\n'
            '  "extends": ["config:recommended"],\n'
            '}\n'
        )
        d, p = write_temp_text(text, name="renovate.json")
        try:
            r = scan_file(p, Options())
            self.assertEqual(r.verdict, Verdict.HEALTHY)
            self.assertEqual(r.findings, [])
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
