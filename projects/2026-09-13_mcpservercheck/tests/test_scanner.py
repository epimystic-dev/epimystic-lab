"""Tests for mcpservercheck.scanner."""

import io
import json
import os
import tempfile
import unittest

from mcpservercheck.parse import BOM
from mcpservercheck.scanner import (
    DEFAULT_GLOBS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    discover,
    read_text,
    scan_file,
    scan_path,
)


class ReadTextTests(unittest.TestCase):
    def test_utf8(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
            f.write(b'{"a": 1}')
            path = f.name
        try:
            self.assertEqual(read_text(path), '{"a": 1}')
        finally:
            os.unlink(path)

    def test_bom_strip(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
            f.write(b"\xef\xbb\xbf" + b'{"a": 1}')
            path = f.name
        try:
            self.assertEqual(read_text(path), '{"a": 1}')
        finally:
            os.unlink(path)

    def test_latin1_fallback(self):
        # invalid utf-8 sequence 0x81 in latin-1 range
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
            f.write(b"\x81\x82\x83")
            path = f.name
        try:
            out = read_text(path)
            self.assertEqual(len(out), 3)
        finally:
            os.unlink(path)

    def test_max_bytes_cap(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
            f.write(b"a" * 5000)
            path = f.name
        try:
            self.assertEqual(len(read_text(path, max_bytes=100)), 100)
        finally:
            os.unlink(path)


class DiscoverTests(unittest.TestCase):
    def test_missing_path(self):
        self.assertEqual(discover(os.path.join(tempfile.gettempdir(), "nope-xyz-123")), [])

    def test_single_file_match(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{}")
            path = f.name
        try:
            self.assertEqual(discover(path), [path])
        finally:
            os.unlink(path)

    def test_single_file_miss(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("{}")
            path = f.name
        try:
            self.assertEqual(discover(path), [])
        finally:
            os.unlink(path)

    def test_dir_walk_json(self):
        d = tempfile.mkdtemp()
        try:
            for name in ("a.json", "b.jsonl", "c.txt"):
                with open(os.path.join(d, name), "w") as f:
                    f.write("{}")
            hits = discover(d)
            names = sorted(os.path.basename(p) for p in hits)
            self.assertEqual(names, ["a.json", "b.jsonl"])
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_case_insensitive(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "MCP.JSON"), "w") as f:
                f.write("{}")
            hits = discover(d)
            self.assertEqual(len(hits), 1)
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_max_files_cap(self):
        d = tempfile.mkdtemp()
        try:
            for i in range(10):
                with open(os.path.join(d, "f" + str(i) + ".json"), "w") as f:
                    f.write("{}")
            hits = discover(d, max_files=3)
            self.assertEqual(len(hits), 3)
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_deterministic_order(self):
        d = tempfile.mkdtemp()
        try:
            for name in ("z.json", "a.json", "m.json"):
                with open(os.path.join(d, name), "w") as f:
                    f.write("{}")
            hits = discover(d)
            names = [os.path.basename(p) for p in hits]
            self.assertEqual(names, sorted(names))
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_custom_glob(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "example.mcp.json"), "w") as f:
                f.write("{}")
            hits = discover(d, globs=("*.mcp.json",))
            self.assertEqual(len(hits), 1)
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)


class ScanFileTests(unittest.TestCase):
    def test_json_healthy(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"mcpServers": {"s": {"command": "/usr/bin/server", "description": "d"}}}, f)
            path = f.name
        try:
            fs, err = scan_file(path)
            self.assertIsNone(err)
            self.assertEqual(fs, [])
        finally:
            os.unlink(path)

    def test_json_unhealthy(self):
        cfg = {"mcpServers": {"s": {"command": "/bin/bash", "args": ["-c", "x"]}}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            path = f.name
        try:
            fs, err = scan_file(path)
            self.assertIsNone(err)
            self.assertTrue(any(f.rule_id == "MSC-001" for f in fs))
        finally:
            os.unlink(path)

    def test_jsonl_per_line(self):
        line1 = json.dumps({"mcpServers": {"a": {"command": "/bin/bash", "args": ["-c", "x"]}}})
        line2 = json.dumps({"mcpServers": {"b": {"command": "/usr/bin/server", "description": "d"}}})
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write(line1 + "\n" + line2 + "\n")
            path = f.name
        try:
            fs, err = scan_file(path)
            self.assertIsNone(err)
            lines = sorted(set(f.line for f in fs))
            self.assertEqual(lines, [1])
        finally:
            os.unlink(path)

    def test_invalid_json_no_crash(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{not-json")
            path = f.name
        try:
            fs, err = scan_file(path)
            self.assertIsNone(err)
            self.assertEqual(fs, [])
        finally:
            os.unlink(path)

    def test_disable_rule(self):
        cfg = {"mcpServers": {"s": {"command": "/bin/bash", "args": ["-c", "x"]}}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f)
            path = f.name
        try:
            fs, err = scan_file(path, disabled=frozenset({"MSC-001"}))
            self.assertFalse(any(f.rule_id == "MSC-001" for f in fs))
        finally:
            os.unlink(path)


class ScanPathTests(unittest.TestCase):
    def test_empty_dir(self):
        d = tempfile.mkdtemp()
        try:
            r = scan_path(d)
            self.assertEqual(r.files_scanned, 0)
            self.assertEqual(r.findings, ())
        finally:
            os.rmdir(d)

    def test_findings_sorted(self):
        d = tempfile.mkdtemp()
        try:
            for name in ("a.json", "b.json"):
                cfg = {"mcpServers": {"s": {"command": "/bin/bash", "args": ["-c", "x"]}}}
                with open(os.path.join(d, name), "w") as f:
                    json.dump(cfg, f)
            r = scan_path(d)
            self.assertGreaterEqual(len(r.findings), 2)
            paths = [f.path for f in r.findings]
            self.assertEqual(paths, sorted(paths))
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_disable_suppresses(self):
        d = tempfile.mkdtemp()
        try:
            cfg = {"mcpServers": {"s": {"command": "/bin/bash", "args": ["-c", "x"]}}}
            with open(os.path.join(d, "a.json"), "w") as f:
                json.dump(cfg, f)
            r = scan_path(d, disabled=frozenset({"MSC-001"}))
            self.assertFalse(any(f.rule_id == "MSC-001" for f in r.findings))
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_max_files_cap(self):
        d = tempfile.mkdtemp()
        try:
            for i in range(5):
                with open(os.path.join(d, "f" + str(i) + ".json"), "w") as f:
                    json.dump({}, f)
            r = scan_path(d, max_files=2)
            self.assertEqual(r.files_scanned, 2)
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)


class DefaultConstantsTests(unittest.TestCase):
    def test_default_globs_include_json_and_jsonl(self):
        self.assertIn("*.json", DEFAULT_GLOBS)
        self.assertIn("*.jsonl", DEFAULT_GLOBS)

    def test_default_max_files_positive(self):
        self.assertGreater(DEFAULT_MAX_FILES, 0)

    def test_default_max_bytes_positive(self):
        self.assertGreater(DEFAULT_MAX_BYTES, 0)


if __name__ == "__main__":
    unittest.main()
