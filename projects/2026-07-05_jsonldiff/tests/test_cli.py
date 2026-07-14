"""End-to-end CLI tests."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from jsonldiff.cli import main


class CLIFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jsonldiff_")

    def tearDown(self):
        for p in Path(self.tmp).glob("*"):
            p.unlink()
        os.rmdir(self.tmp)

    def _write(self, name: str, content: str) -> str:
        p = Path(self.tmp) / name
        p.write_text(content, encoding="utf-8", newline="")
        return str(p)


class CLIBehavior(CLIFixture):
    def test_equal_returns_zero(self):
        a = self._write("a.jsonl", '{"x":1}\n')
        b = self._write("b.jsonl", '{"x":1}\n')
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main([a, b, "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "")

    def test_differences_default_still_zero_without_exit_code(self):
        a = self._write("a.jsonl", '{"x":1}\n')
        b = self._write("b.jsonl", '{"x":2}\n')
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main([a, b, "--quiet"])
        self.assertEqual(rc, 0)
        self.assertIn("x:", out.getvalue())

    def test_exit_code_flag_returns_one_on_diffs(self):
        a = self._write("a.jsonl", '{"x":1}\n')
        b = self._write("b.jsonl", '{"x":2}\n')
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = main([a, b, "--exit-code", "--quiet"])
        self.assertEqual(rc, 1)

    def test_missing_input_returns_two(self):
        a = self._write("a.jsonl", '{"x":1}\n')
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            rc = main([a, "no-such-file.jsonl"])
        self.assertEqual(rc, 2)

    def test_parse_error_returns_two(self):
        a = self._write("a.jsonl", "not-json\n")
        b = self._write("b.jsonl", '{"x":1}\n')
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = main([a, b, "--quiet"])
        self.assertEqual(rc, 2)

    def test_json_format_emits_ndjson(self):
        a = self._write("a.jsonl", '{"x":1,"y":2}\n')
        b = self._write("b.jsonl", '{"x":9,"y":2}\n')
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            main([a, b, "--format", "json", "--quiet"])
        records = [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "changed")
        self.assertEqual(records[0]["path"], "x")
        self.assertEqual(records[0]["baseline"], 1)
        self.assertEqual(records[0]["candidate"], 9)

    def test_ignore_flag_repeats(self):
        a = self._write("a.jsonl", '{"m":{"acc":1},"t":1}\n')
        b = self._write("b.jsonl", '{"m":{"acc":2},"t":2}\n')
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = main([a, b, "--ignore", "m", "--ignore", "t", "--exit-code", "--quiet"])
        self.assertEqual(rc, 0)

    def test_key_mode(self):
        a = self._write("a.jsonl", '{"id":"a","v":1}\n{"id":"b","v":2}\n')
        b = self._write("b.jsonl", '{"id":"b","v":22}\n{"id":"a","v":1}\n')
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            rc = main([a, b, "--key", "id", "--format", "json", "--exit-code", "--quiet"])
        self.assertEqual(rc, 1)
        records = [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["key"], "b")


if __name__ == "__main__":
    unittest.main()
