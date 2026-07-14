import io
import json
import os
import tempfile
import unittest

from jsonlsample.__main__ import run


def _write_jsonl(records, suffix=".jsonl") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


class TestCLI(unittest.TestCase):
    def setUp(self):
        self._paths = []

    def tearDown(self):
        for p in self._paths:
            try:
                os.remove(p)
            except OSError:
                pass

    def _mkfile(self, records):
        p = _write_jsonl(records)
        self._paths.append(p)
        return p

    def test_reservoir_mode(self):
        records = [{"i": i} for i in range(200)]
        path = self._mkfile(records)
        stdout = io.StringIO()
        rc = run(
            [path, "-n", "10", "--seed", "42"],
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 0)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 10)
        for line in lines:
            obj = json.loads(line)
            self.assertIn("i", obj)
            self.assertTrue(0 <= obj["i"] < 200)

    def test_reservoir_reproducible(self):
        records = [{"i": i} for i in range(200)]
        path = self._mkfile(records)
        out1, out2 = io.StringIO(), io.StringIO()
        run([path, "-n", "10", "--seed", "42"], stdout=out1, stderr=io.StringIO())
        run([path, "-n", "10", "--seed", "42"], stdout=out2, stderr=io.StringIO())
        self.assertEqual(out1.getvalue(), out2.getvalue())

    def test_fraction_mode(self):
        records = [{"i": i} for i in range(2000)]
        path = self._mkfile(records)
        stdout = io.StringIO()
        rc = run(
            [path, "--fraction", "0.1", "--seed", "0"],
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 0)
        n_out = len(stdout.getvalue().splitlines())
        # Binomial(2000, 0.1): mean 200, sd ~13.4; 6-sigma window is 80.
        self.assertTrue(120 <= n_out <= 280, n_out)

    def test_stratify_mode(self):
        records = []
        for _ in range(50):
            records.append({"label": "a", "id": 1})
        for _ in range(50):
            records.append({"label": "b", "id": 2})
        for _ in range(50):
            records.append({"label": "c", "id": 3})
        path = self._mkfile(records)
        stdout = io.StringIO()
        rc = run(
            [path, "--stratify", "label", "--per-group", "5", "--seed", "3"],
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 0)
        emitted = [json.loads(l) for l in stdout.getvalue().splitlines()]
        self.assertEqual(len(emitted), 15)
        labels = [r["label"] for r in emitted]
        self.assertEqual(labels.count("a"), 5)
        self.assertEqual(labels.count("b"), 5)
        self.assertEqual(labels.count("c"), 5)

    def test_stratify_nested_path(self):
        records = [
            {"meta": {"cat": "x"}, "id": i} for i in range(20)
        ] + [
            {"meta": {"cat": "y"}, "id": i + 100} for i in range(20)
        ]
        path = self._mkfile(records)
        stdout = io.StringIO()
        rc = run(
            [path, "--stratify", "meta.cat", "--per-group", "3", "--seed", "0"],
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 0)
        emitted = [json.loads(l) for l in stdout.getvalue().splitlines()]
        cats = [r["meta"]["cat"] for r in emitted]
        self.assertEqual(cats.count("x"), 3)
        self.assertEqual(cats.count("y"), 3)

    def test_stratify_missing_key_group(self):
        records = [
            {"label": "a", "id": 1},
            {"id": 2},
            {"label": "a", "id": 3},
        ]
        path = self._mkfile(records)
        stdout = io.StringIO()
        rc = run(
            [path, "--stratify", "label", "--per-group", "5", "--seed", "0"],
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 0)
        # 3 records emitted: 2 in group 'a' + 1 in the missing group.
        self.assertEqual(len(stdout.getvalue().splitlines()), 3)

    def test_parse_error_exit_2(self):
        # Handcrafted bad JSONL.
        path = self._mkfile([])
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"good": 1}\n')
            f.write("not json\n")
            f.write('{"good": 2}\n')
        stderr = io.StringIO()
        rc = run(
            [path, "-n", "10", "--seed", "0"],
            stdout=io.StringIO(),
            stderr=stderr,
        )
        self.assertEqual(rc, 2)
        self.assertIn("parse error", stderr.getvalue())

    def test_parse_error_skipped_yields_zero(self):
        path = self._mkfile([])
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"good": 1}\n')
            f.write("not json\n")
            f.write('{"good": 2}\n')
        rc = run(
            [path, "-n", "10", "--skip-parse-errors"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 0)

    def test_empty_input_returns_1(self):
        path = self._mkfile([])
        rc = run(
            [path, "-n", "10"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 1)

    def test_fraction_out_of_range_rejected(self):
        path = self._mkfile([{"i": 0}])
        stderr = io.StringIO()
        rc = run(
            [path, "--fraction", "1.5"],
            stdout=io.StringIO(),
            stderr=stderr,
        )
        self.assertEqual(rc, 2)
        self.assertIn("--fraction must be", stderr.getvalue())

    def test_missing_file(self):
        stderr = io.StringIO()
        rc = run(
            ["/no/such/file.jsonl", "-n", "5"],
            stdout=io.StringIO(),
            stderr=stderr,
        )
        self.assertEqual(rc, 2)

    def test_mutually_exclusive_modes(self):
        path = self._mkfile([{"i": 0}])
        # argparse SystemExits with code 2 on mutex violation.
        with self.assertRaises(SystemExit):
            run(
                [path, "-n", "5", "--fraction", "0.1"],
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )


if __name__ == "__main__":
    unittest.main()
