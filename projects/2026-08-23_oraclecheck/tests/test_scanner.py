"""Scanner discovery + read tests."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from oraclecheck.config import Config, DEFAULT_TEST_GLOBS
from oraclecheck.scanner import (
    discover_test_files,
    infer_sut_module,
    read_source,
    scan_path,
)


class TestInferSut(unittest.TestCase):

    def test_test_prefix(self):
        self.assertEqual(infer_sut_module("test_foo.py"), "foo")

    def test_test_prefix_nested(self):
        self.assertEqual(infer_sut_module("tests/test_foo.py"), "foo")

    def test_suffix(self):
        self.assertEqual(infer_sut_module("foo_test.py"), "foo")

    def test_no_match_returns_none(self):
        self.assertIsNone(infer_sut_module("helpers.py"))

    def test_not_python_returns_none(self):
        self.assertIsNone(infer_sut_module("test_foo.txt"))

    def test_bare_tests_py_returns_none(self):
        self.assertIsNone(infer_sut_module("tests.py"))


class _TempTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oc-scan-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel: str, content: str = "") -> str:
        p = Path(self.tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return str(p)


class TestDiscovery(_TempTree):

    def test_discovers_test_prefix(self):
        self._write("tests/test_a.py")
        self._write("tests/test_b.py")
        files = discover_test_files(self.tmp, Config())
        self.assertEqual(len(files), 2)

    def test_discovers_suffix(self):
        self._write("pkg/foo_test.py")
        files = discover_test_files(self.tmp, Config())
        self.assertEqual(len(files), 1)

    def test_ignores_non_test_files(self):
        self._write("pkg/helpers.py")
        files = discover_test_files(self.tmp, Config())
        self.assertEqual(files, [])

    def test_single_file_path_returns_singleton(self):
        p = self._write("standalone.py", "x = 1\n")
        files = discover_test_files(p, Config())
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].endswith("standalone.py"))

    def test_missing_path_returns_empty(self):
        files = discover_test_files(os.path.join(self.tmp, "nope"), Config())
        self.assertEqual(files, [])

    def test_deterministic_order(self):
        for rel in ["tests/test_c.py", "tests/test_a.py", "tests/test_b.py"]:
            self._write(rel)
        files1 = discover_test_files(self.tmp, Config())
        files2 = discover_test_files(self.tmp, Config())
        self.assertEqual(files1, files2)
        self.assertEqual(files1, sorted(files1))

    def test_max_files_cap(self):
        for i in range(5):
            self._write(f"tests/test_{i}.py")
        cfg = Config(max_files=3)
        files = discover_test_files(self.tmp, cfg)
        self.assertEqual(len(files), 3)

    def test_case_insensitive_match(self):
        self._write("tests/TEST_FOO.PY")
        files = discover_test_files(self.tmp, Config())
        self.assertEqual(len(files), 1)

    def test_custom_glob_via_config(self):
        self._write("pkg/spec_foo.py")
        cfg = Config(test_globs=DEFAULT_TEST_GLOBS + ("spec_*.py",))
        files = discover_test_files(self.tmp, cfg)
        self.assertEqual(len(files), 1)


class TestReadSource(_TempTree):

    def _write_bytes(self, rel, data: bytes) -> str:
        p = Path(self.tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return str(p)

    def test_reads_utf8(self):
        p = self._write_bytes("a.py", b"x = 1\n")
        text, err = read_source(p, Config())
        self.assertIsNone(err)
        self.assertEqual(text, "x = 1\n")

    def test_strips_utf8_bom(self):
        p = self._write_bytes("a.py", b"\xef\xbb\xbfx = 1\n")
        text, err = read_source(p, Config())
        self.assertIsNone(err)
        self.assertEqual(text, "x = 1\n")

    def test_latin1_fallback(self):
        p = os.path.join(self.tmp, "a.py")
        with open(p, "wb") as f:
            f.write(b"x = \xff\n")  # invalid utf-8
        text, err = read_source(p, Config())
        self.assertIsNone(err)
        self.assertIn("x = ", text)

    def test_missing_file(self):
        text, err = read_source(os.path.join(self.tmp, "nope.py"), Config())
        self.assertIsNone(text)
        self.assertIn("file not found", err)

    def test_max_bytes_truncates(self):
        content = "# " + ("A" * 1000) + "\n"
        p = self._write("a.py", content)
        cfg = Config(max_bytes=100)
        text, err = read_source(p, Config(max_bytes=100))
        self.assertIsNone(err)
        self.assertLessEqual(len(text), 100)


class TestScanPath(_TempTree):

    def test_healthy_file_produces_no_findings(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  self.assertEqual(compute(1), 2)\n"
        )
        self._write("test_foo.py", src)
        results = scan_path(self.tmp, Config(sut_module=None))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].findings, [])

    def test_anchored_file_produces_high(self):
        src = (
            "class T:\n"
            " def test_x(self):\n"
            "  expected = foo.compute(1)\n"
            "  self.assertEqual(foo.compute(1), expected)\n"
        )
        self._write("test_foo.py", src)
        results = scan_path(self.tmp, Config())
        # SUT inferred from test_foo.py -> 'foo'; ORACLE-002 should fire.
        rule_ids = [f.rule_id for f in results[0].findings]
        self.assertIn("ORACLE-002", rule_ids)

    def test_syntax_error_reports_but_does_not_crash(self):
        self._write("test_foo.py", "def broken(:\n")
        results = scan_path(self.tmp, Config())
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].error, "syntax error")
        self.assertEqual(results[0].findings, [])

    def test_empty_directory_returns_empty(self):
        results = scan_path(self.tmp, Config())
        self.assertEqual(results, [])

    def test_single_file_scan(self):
        p = self._write("test_x.py", "def test_a():\n assert True\n")
        results = scan_path(p, Config())
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
