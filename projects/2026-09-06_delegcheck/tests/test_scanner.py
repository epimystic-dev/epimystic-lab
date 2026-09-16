import json
import os
import tempfile
import unittest

from delegcheck.scanner import (
    DEFAULT_GLOBS,
    discover,
    read_text,
    scan_file,
    scan_path,
)
from delegcheck.types import ScanResult


class _TmpTree:

    def __enter__(self):
        self.d = tempfile.mkdtemp(prefix="delegcheck-test-")
        return self

    def __exit__(self, *a):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def write(self, rel, content):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p) or self.d, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        return p


class TestReadText(unittest.TestCase):

    def test_reads_utf8(self):
        with _TmpTree() as t:
            p = t.write("a.json", '{"x": 1}\n')
            self.assertEqual(read_text(p), '{"x": 1}\n')

    def test_strips_bom(self):
        with _TmpTree() as t:
            p = t.write("a.json", "\ufeff" + '{"x": 1}\n')
            self.assertEqual(read_text(p), '{"x": 1}\n')

    def test_latin1_fallback(self):
        with _TmpTree() as t:
            path = os.path.join(t.d, "b.json")
            with open(path, "wb") as f:
                f.write(b"\xff\xfe\xfd not utf-8")
            got = read_text(path)
            self.assertIsInstance(got, str)

    def test_max_bytes_cap(self):
        with _TmpTree() as t:
            p = t.write("a.json", "x" * 5000)
            self.assertEqual(len(read_text(p, max_bytes=100)), 100)


class TestDiscover(unittest.TestCase):

    def test_missing_path(self):
        self.assertEqual(discover("/does/not/exist/anywhere"), [])

    def test_single_file_match(self):
        with _TmpTree() as t:
            p = t.write("a.json", "{}")
            self.assertEqual(discover(p), [p])

    def test_single_file_miss(self):
        with _TmpTree() as t:
            p = t.write("a.txt", "hi")
            self.assertEqual(discover(p), [])

    def test_dir_walk_json(self):
        with _TmpTree() as t:
            p1 = t.write("one.json", "{}")
            p2 = t.write("sub/two.json", "{}")
            found = discover(t.d)
            self.assertEqual(
                sorted(os.path.normpath(x) for x in found),
                sorted(os.path.normpath(x) for x in [p1, p2]),
            )

    def test_case_insensitive(self):
        with _TmpTree() as t:
            p = t.write("A.JSON", "{}")
            found = discover(t.d)
            self.assertEqual(found, [p])

    def test_max_files_cap(self):
        with _TmpTree() as t:
            for i in range(5):
                t.write("f{}.json".format(i), "{}")
            found = discover(t.d, max_files=3)
            self.assertEqual(len(found), 3)

    def test_deterministic_order(self):
        with _TmpTree() as t:
            for name in ["z.json", "a.json", "m.json"]:
                t.write(name, "{}")
            found = discover(t.d)
            self.assertEqual(found, sorted(found))

    def test_custom_glob(self):
        with _TmpTree() as t:
            p_json = t.write("a.json", "{}")
            p_log = t.write("b.log", "{}")
            self.assertEqual(discover(t.d, globs=("*.log",)), [p_log])
            self.assertEqual(discover(t.d, globs=("*.log", "*.json")), sorted([p_json, p_log]))

    def test_jsonl_default(self):
        with _TmpTree() as t:
            p = t.write("a.jsonl", "{}")
            self.assertEqual(discover(t.d), [p])


class TestScanFile(unittest.TestCase):

    def test_scan_json_healthy(self):
        with _TmpTree() as t:
            obj = {
                "credentials": [{
                    "name": "t", "type": "bearer", "value_ref": "vault://t",
                    "scope": "read:issues", "expires_at": "2026-10-01",
                }],
                "tools": [{"name": "list", "principal": "w"}],
            }
            p = t.write("a.json", json.dumps(obj, indent=2))
            findings, err = scan_file(p)
            self.assertEqual(findings, [])
            self.assertIsNone(err)

    def test_scan_json_unhealthy(self):
        with _TmpTree() as t:
            obj = {
                "credentials": [{
                    "name": "t", "type": "bearer", "value_ref": "vault://t", "scope": "*",
                }],
            }
            p = t.write("a.json", json.dumps(obj, indent=2))
            findings, err = scan_file(p)
            self.assertGreaterEqual(len(findings), 1)
            self.assertIsNone(err)

    def test_scan_jsonl_per_line(self):
        with _TmpTree() as t:
            lines = [
                json.dumps({"authorization": {"mode": "llm"}}),
                json.dumps({"authorization": {"mode": "external"}}),
                json.dumps({"authorization": {"mode": "llm"}}),
            ]
            p = t.write("a.jsonl", "\n".join(lines) + "\n")
            findings, err = scan_file(p)
            self.assertEqual(len(findings), 2)
            self.assertEqual({f.line for f in findings}, {1, 3})

    def test_scan_invalid_json_no_findings_no_crash(self):
        with _TmpTree() as t:
            p = t.write("a.json", "not json at all")
            findings, err = scan_file(p)
            self.assertEqual(findings, [])
            self.assertIsNone(err)

    def test_disabled_rule_suppressed(self):
        with _TmpTree() as t:
            obj = {"authorization": {"mode": "llm"}}
            p = t.write("a.json", json.dumps(obj, indent=2))
            findings, err = scan_file(p, disabled=frozenset({"DEL-003"}))
            self.assertEqual(findings, [])


class TestScanPath(unittest.TestCase):

    def test_empty_dir_no_files_scanned(self):
        with _TmpTree() as t:
            r = scan_path(t.d)
            self.assertEqual(r.files_scanned, 0)
            self.assertEqual(r.findings, tuple())

    def test_findings_sorted(self):
        with _TmpTree() as t:
            obj_a = {"authorization": {"mode": "llm"}, "tools": [{"name": "t"}]}
            obj_b = {"authorization": {"mode": "model"}}
            t.write("a.json", json.dumps(obj_a, indent=2))
            t.write("b.json", json.dumps(obj_b, indent=2))
            r = scan_path(t.d)
            self.assertGreater(len(r.findings), 0)
            keys = [f.sort_key() for f in r.findings]
            self.assertEqual(keys, sorted(keys))

    def test_disable_suppresses(self):
        with _TmpTree() as t:
            t.write("a.json", json.dumps({"authorization": {"mode": "llm"}}))
            r_all = scan_path(t.d)
            r_dis = scan_path(t.d, disabled=frozenset({"DEL-003"}))
            self.assertGreater(len(r_all.findings), 0)
            self.assertEqual(r_dis.findings, tuple())

    def test_max_files_cap(self):
        with _TmpTree() as t:
            for i in range(5):
                t.write("f{}.json".format(i), json.dumps({"authorization": {"mode": "llm"}}))
            r = scan_path(t.d, max_files=2)
            self.assertEqual(r.files_scanned, 2)


if __name__ == "__main__":
    unittest.main()
