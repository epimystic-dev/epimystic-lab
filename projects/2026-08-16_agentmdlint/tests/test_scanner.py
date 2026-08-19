import os
import shutil
import tempfile
import unittest

from agentmdlint.config import Config
from agentmdlint.scanner import discover_files, read_file, scan_path


class TempRepo:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="agentmdlint_test_")

    def write(self, rel, content, encoding="utf-8"):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full) or self.root, exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content.encode(encoding))
        return full

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()

    def tearDown(self):
        self.repo.cleanup()

    def test_canonical_agents_md_found(self):
        self.repo.write("AGENTS.md", "# a\n")
        hits = discover_files(self.repo.root, Config())
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].endswith("AGENTS.md"))

    def test_case_insensitive_filename(self):
        self.repo.write("agents.md", "# a\n")
        hits = discover_files(self.repo.root, Config())
        self.assertEqual(len(hits), 1)

    def test_multiple_files_deterministic_order(self):
        self.repo.write("AGENTS.md", "# a\n")
        self.repo.write("CLAUDE.md", "# c\n")
        self.repo.write("GEMINI.md", "# g\n")
        hits = discover_files(self.repo.root, Config())
        self.assertEqual(len(hits), 3)
        self.assertEqual(hits, sorted(hits))

    def test_nested_copilot_instructions(self):
        self.repo.write(".github/copilot-instructions.md", "# hi\n")
        hits = discover_files(self.repo.root, Config())
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].endswith("copilot-instructions.md"))

    def test_no_matches_returns_empty(self):
        self.repo.write("README.md", "# not an agent file\n")
        hits = discover_files(self.repo.root, Config())
        self.assertEqual(hits, [])

    def test_missing_path_returns_empty(self):
        hits = discover_files(os.path.join(self.repo.root, "no_such"), Config())
        self.assertEqual(hits, [])

    def test_single_file_path_passed_directly(self):
        f = self.repo.write("RANDOM.md", "# a\n")
        hits = discover_files(f, Config())
        self.assertEqual(hits, [os.path.normpath(f)])

    def test_max_files_cap(self):
        # write more than cfg.max_files
        for name in ["AGENTS.md", "AGENT.md", "CLAUDE.md", "GEMINI.md", "CURSOR.md"]:
            self.repo.write(name, "# a\n")
        cfg = Config(max_files=2)
        hits = discover_files(self.repo.root, cfg)
        self.assertEqual(len(hits), 2)

    def test_custom_files_override(self):
        self.repo.write("MY_INSTRUCTIONS.md", "# mine\n")
        cfg = Config(files=("MY_INSTRUCTIONS.md",))
        hits = discover_files(self.repo.root, cfg)
        self.assertEqual(len(hits), 1)


class TestReadFile(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()

    def tearDown(self):
        self.repo.cleanup()

    def test_utf8_read(self):
        f = self.repo.write("t.md", "hello")
        text, size, err = read_file(f, Config())
        self.assertIsNone(err)
        self.assertEqual(text, "hello")
        self.assertEqual(size, 5)

    def test_bom_stripped(self):
        full = os.path.join(self.repo.root, "t.md")
        with open(full, "wb") as fh:
            fh.write(b"\xef\xbb\xbfhello")
        text, _, err = read_file(full, Config())
        self.assertIsNone(err)
        self.assertEqual(text, "hello")

    def test_latin1_fallback(self):
        full = os.path.join(self.repo.root, "t.md")
        with open(full, "wb") as fh:
            fh.write(b"caf\xe9")
        text, _, err = read_file(full, Config())
        self.assertIsNone(err)
        self.assertTrue(text.endswith("\xe9") or text.startswith("caf"))

    def test_missing_file_error(self):
        text, _, err = read_file(os.path.join(self.repo.root, "no_such.md"), Config())
        self.assertIsNotNone(err)
        self.assertEqual(text, "")

    def test_max_bytes_truncation(self):
        big = "a" * 1024
        f = self.repo.write("t.md", big)
        cfg = Config(max_bytes=100)
        text, size, err = read_file(f, Config(max_bytes=100))
        self.assertIsNone(err)
        self.assertEqual(len(text), 100)
        self.assertEqual(size, 100)


class TestScanPath(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()

    def tearDown(self):
        self.repo.cleanup()

    def test_empty_repo_no_files(self):
        report = scan_path(self.repo.root, Config())
        self.assertEqual(report.file_reports, [])
        self.assertEqual(report.files_scanned(), 0)

    def test_healthy_file(self):
        self.repo.write(
            "AGENTS.md",
            "# Project Agent Guide\n\nThis file documents how the agent operates in this project.\n\nAll instructions include a rationale.\n",
        )
        report = scan_path(self.repo.root, Config())
        self.assertEqual(report.files_scanned(), 1)

    def test_deterministic_ordering(self):
        self.repo.write("AGENTS.md", "# a\n")
        self.repo.write("CLAUDE.md", "# c\n")
        r1 = scan_path(self.repo.root, Config())
        r2 = scan_path(self.repo.root, Config())
        self.assertEqual([fr.path for fr in r1.file_reports], [fr.path for fr in r2.file_reports])

    def test_missing_path_returns_empty_report(self):
        report = scan_path(os.path.join(self.repo.root, "missing"), Config())
        self.assertEqual(report.file_reports, [])

    def test_single_file_direct(self):
        f = self.repo.write("MY.md", "# doc\n\nThis file exists.\n")
        report = scan_path(f, Config())
        self.assertEqual(len(report.file_reports), 1)


if __name__ == "__main__":
    unittest.main()
