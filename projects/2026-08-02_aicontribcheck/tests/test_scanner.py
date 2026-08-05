"""Tests for the file discovery / read layer."""

import os
import tempfile
import unittest
from pathlib import Path

from aicontribcheck.scanner import (
    MAX_FILE_BYTES,
    MAX_FILES,
    discover_policy_files,
    iter_lines,
    read_policy_file,
)


HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"


class DiscoveryTests(unittest.TestCase):
    def test_ban_repo_finds_two_files(self):
        found = discover_policy_files(str(FIXTURES / "ban_repo"))
        kinds = sorted(k for k, _ in found)
        self.assertEqual(kinds, ["contributing", "readme"])

    def test_conditional_repo_finds_root_and_dot_github(self):
        found = discover_policy_files(str(FIXTURES / "conditional_repo"))
        kinds = sorted(k for k, _ in found)
        self.assertIn("contributing", kinds)
        self.assertIn("ai-policy", kinds)

    def test_case_insensitive_match(self):
        with tempfile.TemporaryDirectory() as td:
            for name in ("contributing.md", "Readme.RST", "AGENTS.md"):
                Path(td, name).write_text("x", encoding="utf-8")
            found = discover_policy_files(td)
            kinds = sorted(k for k, _ in found)
            self.assertEqual(kinds, ["agents", "contributing", "readme"])

    def test_single_file_target(self):
        p = FIXTURES / "conditional_repo" / ".github" / "AI_POLICY.md"
        found = discover_policy_files(str(p))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], "ai-policy")

    def test_single_file_unknown_kind(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False
        ) as fh:
            fh.write("nothing")
            path = fh.name
        try:
            found = discover_policy_files(path)
            self.assertEqual(found[0][0], "unknown")
        finally:
            os.unlink(path)

    def test_nonexistent_path(self):
        self.assertEqual(discover_policy_files("/no/such/path/here-999"), [])

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(discover_policy_files(td), [])

    def test_no_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "README.md").write_text("x", encoding="utf-8")
            found = discover_policy_files(td)
            paths = [p for _, p in found]
            self.assertEqual(len(paths), len(set(paths)))

    def test_directory_with_matching_name_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            # A directory named CONTRIBUTING.md should not be picked as a file.
            os.mkdir(os.path.join(td, "CONTRIBUTING.md"))
            found = discover_policy_files(td)
            self.assertEqual(found, [])

    def test_deterministic_order(self):
        with tempfile.TemporaryDirectory() as td:
            for name in (
                "README.md",
                "CONTRIBUTING.md",
                "AGENTS.md",
                "LICENSE",
            ):
                Path(td, name).write_text("x", encoding="utf-8")
            a = discover_policy_files(td)
            b = discover_policy_files(td)
            self.assertEqual(a, b)


class ReadTests(unittest.TestCase):
    def test_reads_utf8(self):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".md", delete=False
        ) as fh:
            fh.write("# hello world".encode("utf-8"))
            path = fh.name
        try:
            text, err = read_policy_file(path)
            self.assertIsNone(err)
            self.assertEqual(text, "# hello world")
        finally:
            os.unlink(path)

    def test_strips_utf8_bom(self):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".md", delete=False
        ) as fh:
            fh.write(b"\xef\xbb\xbf" + "text".encode("utf-8"))
            path = fh.name
        try:
            text, err = read_policy_file(path)
            self.assertIsNone(err)
            self.assertEqual(text, "text")
        finally:
            os.unlink(path)

    def test_falls_back_to_latin1(self):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".md", delete=False
        ) as fh:
            # 0xff is invalid UTF-8 but valid latin-1
            fh.write(b"hello \xff world")
            path = fh.name
        try:
            text, err = read_policy_file(path)
            self.assertIsNone(err)
            self.assertIn("hello", text)
        finally:
            os.unlink(path)

    def test_rejects_oversize_file(self):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".md", delete=False
        ) as fh:
            fh.write(b"x" * (MAX_FILE_BYTES + 1))
            path = fh.name
        try:
            text, err = read_policy_file(path)
            self.assertIsNone(text)
            self.assertIn("too large", err)
        finally:
            os.unlink(path)

    def test_missing_file_returns_error(self):
        text, err = read_policy_file("/no/such/file/999-xyz")
        self.assertIsNone(text)
        self.assertTrue(err)


class IterLinesTests(unittest.TestCase):
    def test_line_numbers_1_indexed(self):
        rows = list(iter_lines("a\nb\nc"))
        self.assertEqual(rows, [(1, "a"), (2, "b"), (3, "c")])

    def test_empty_text_yields_nothing(self):
        self.assertEqual(list(iter_lines("")), [])

    def test_crlf_normalized(self):
        rows = list(iter_lines("a\r\nb\r\n"))
        self.assertEqual(rows, [(1, "a"), (2, "b")])


class CapsTests(unittest.TestCase):
    def test_caps_are_reasonable_positive_ints(self):
        self.assertGreater(MAX_FILE_BYTES, 1024)
        self.assertGreater(MAX_FILES, 1)


if __name__ == "__main__":
    unittest.main()
