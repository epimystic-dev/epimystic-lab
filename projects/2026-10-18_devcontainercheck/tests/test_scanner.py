"""Scanner tests - discovery, file read, directory walk."""

from __future__ import annotations

import os
import unittest

from tests import support
from devcontainercheck.scanner import discover_paths, scan_file, scan_paths
from devcontainercheck.types import Options, Verdict


DIGEST = "@sha256:" + ("a" * 64)


class DiscoverPathsTests(unittest.TestCase):
    def test_explicit_file_returned_verbatim(self):
        d, p = support.write_temp_text("{}", name="my.devcontainer.json")
        self.assertEqual(discover_paths(p), [p])

    def test_directory_walk_finds_devcontainer_json(self):
        d, p = support.write_temp_text("{}", name="devcontainer.json")
        found = discover_paths(d)
        self.assertIn(p, found)

    def test_directory_walk_finds_named_variant(self):
        d, p = support.write_temp_text("{}", name="python.devcontainer.json")
        found = discover_paths(d)
        self.assertIn(p, found)

    def test_directory_walk_ignores_unrelated_json(self):
        d, p = support.write_temp_text("{}", name="package.json")
        self.assertEqual(discover_paths(d), [])

    def test_missing_path_returns_empty(self):
        self.assertEqual(
            discover_paths("D:\\no_such_path_12345_abc"),
            [],
        )


class ScanFileTests(unittest.TestCase):
    def test_invalid_json_surfaces_dc_000(self):
        _d, p = support.write_temp_text("{ not valid", name="devcontainer.json")
        r = scan_file(p, Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].rule_id, "DC-000")

    def test_missing_file_surfaces_dc_000(self):
        r = scan_file("D:\\no_such_file_abc_xyz.json", Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(r.findings[0].rule_id, "DC-000")

    def test_healthy_fixture_returns_healthy_verdict(self):
        pkg = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = os.path.join(pkg, "examples", "healthy_devcontainer.json")
        r = scan_file(p, Options())
        self.assertIs(r.verdict, Verdict.HEALTHY, r.findings)

    def test_weak_fixture_returns_unhealthy_verdict(self):
        pkg = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = os.path.join(pkg, "examples", "weak_devcontainer.json")
        r = scan_file(p, Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        ids = {f.rule_id for f in r.findings}
        self.assertIn("DC-001", ids)


class ScanPathsTests(unittest.TestCase):
    def test_scan_two_files_merges(self):
        pkg = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        healthy = os.path.join(pkg, "examples", "healthy_devcontainer.json")
        weak = os.path.join(pkg, "examples", "weak_devcontainer.json")
        r = scan_paths([healthy, weak], Options())
        # Two files; one unhealthy; merge is unhealthy.
        self.assertEqual(r.files_scanned, 2)
        self.assertIs(r.verdict, Verdict.UNHEALTHY)

    def test_scan_directory_discovers_canonical_name(self):
        # discover_paths() only matches the standard
        # devcontainer.json / <name>.devcontainer.json shapes; verify
        # that discipline against a synthesised directory with the
        # canonical filename.
        d, p = support.write_temp_text(
            '{"image": "x@sha256:' + "a" * 64 + '", "remoteUser": "u", "name": "n"}',
            name="devcontainer.json",
        )
        r = scan_paths([d], Options())
        self.assertEqual(r.files_scanned, 1)
        self.assertIs(r.verdict, Verdict.HEALTHY)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
