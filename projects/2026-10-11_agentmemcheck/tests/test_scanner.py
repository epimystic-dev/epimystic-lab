"""Scanner-layer tests (file IO + path walking + verdict rollup)."""

from __future__ import annotations

import os
import shutil
import unittest

from tests import support
from tests.support import build_entry, build_store, write_temp, write_temp_text

from agentmemcheck.scanner import scan_file, scan_paths, scan_text
from agentmemcheck.types import Options, Verdict


class ScanTextTests(unittest.TestCase):
    def test_clean_store_healthy(self):
        obj = build_store([build_entry()])
        import json
        r = scan_text(json.dumps(obj), "x.json", Options())
        self.assertIs(r.verdict, Verdict.HEALTHY)
        self.assertEqual(r.files_scanned, 1)
        self.assertEqual(r.entries_scanned, 1)

    def test_invalid_json_unhealthy(self):
        r = scan_text("not json", "x.json", Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(r.findings[0].rule_id, "AMC-000")


class ScanFileTests(unittest.TestCase):
    def test_round_trip(self):
        obj = build_store([build_entry()])
        d, p = write_temp(obj)
        try:
            r = scan_file(p, Options())
            self.assertIs(r.verdict, Verdict.HEALTHY)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_missing_file_unhealthy(self):
        r = scan_file("/nonexistent/path/x.json", Options())
        self.assertIs(r.verdict, Verdict.UNHEALTHY)
        self.assertEqual(r.findings[0].rule_id, "AMC-000")

    def test_jsonl_file(self):
        import json
        text = (
            json.dumps(build_entry(id="a", content="x"))
            + "\n"
            + json.dumps(build_entry(id="b", content="y"))
            + "\n"
        )
        d, p = write_temp_text(text, name="store.jsonl")
        try:
            r = scan_file(p, Options())
            self.assertEqual(r.entries_scanned, 2)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class ScanPathsTests(unittest.TestCase):
    def test_directory_walks_json_and_jsonl(self):
        import json
        d1, p1 = write_temp(build_store([build_entry(id="a")]))
        try:
            # drop a second json and a jsonl file in the same dir
            p2 = os.path.join(d1, "second.json")
            with open(p2, "w", encoding="utf-8") as f:
                json.dump(build_store([build_entry(id="b")]), f)
            p3 = os.path.join(d1, "third.jsonl")
            with open(p3, "w", encoding="utf-8") as f:
                f.write(json.dumps(build_entry(id="c")) + "\n")
            # drop a non-matching file to confirm it's skipped
            with open(
                os.path.join(d1, "ignore.txt"), "w", encoding="utf-8",
            ) as f:
                f.write("skip me\n")
            r = scan_paths([d1], Options())
            self.assertEqual(r.files_scanned, 3)
            self.assertEqual(r.entries_scanned, 3)
            self.assertIs(r.verdict, Verdict.HEALTHY)
        finally:
            shutil.rmtree(d1, ignore_errors=True)

    def test_no_files_scanned_unknown(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="agentmemcheck_empty_")
        try:
            r = scan_paths([d], Options())
            self.assertEqual(r.files_scanned, 0)
            self.assertIs(r.verdict, Verdict.UNKNOWN)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
