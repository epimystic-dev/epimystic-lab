import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from licensechain.cli import main


CLEAN = {
    "version": 1,
    "chain": [
        {"name": "d", "role": "dataset", "license": "CC0-1.0"},
        {"name": "m", "role": "model", "license": "MIT",
         "trained_on": ["d"], "preserves_notices": True},
    ],
}

WARN_ONLY = {
    "version": 1,
    "chain": [
        {"name": "lib", "role": "library", "license": "Apache-2.0"},
        {"name": "app", "role": "application", "license": "MIT",
         "uses": ["lib"]},
    ],
}

ERROR_MIX = {
    "version": 1,
    "chain": [
        {"name": "d", "role": "dataset", "license": "CC-BY-SA-4.0",
         "preserves_notices": True},
        {"name": "m", "role": "model", "license": "MIT",
         "trained_on": ["d"], "preserves_notices": True},
    ],
}


def _run_cli(argv, stdin_text=""):
    out = io.StringIO()
    err = io.StringIO()
    saved_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin_text)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


class ExitCodeTests(unittest.TestCase):

    def test_clean_manifest_exits_zero(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(CLEAN, f)
            path = f.name
        try:
            code, out, _err = _run_cli([path])
            self.assertEqual(code, 0)
            self.assertIn("no findings", out)
        finally:
            os.remove(path)

    def test_warn_only_manifest_exits_one(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(WARN_ONLY, f)
            path = f.name
        try:
            code, _out, _err = _run_cli([path])
            self.assertEqual(code, 1)
        finally:
            os.remove(path)

    def test_error_manifest_exits_two(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(ERROR_MIX, f)
            path = f.name
        try:
            code, _out, _err = _run_cli([path])
            self.assertEqual(code, 2)
        finally:
            os.remove(path)

    def test_strict_promotes_warn_to_error_exit_code(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(WARN_ONLY, f)
            path = f.name
        try:
            code, _out, _err = _run_cli(["--strict", path])
            self.assertEqual(code, 2)
        finally:
            os.remove(path)


class FormatTests(unittest.TestCase):

    def test_default_text_output(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(WARN_ONLY, f)
            path = f.name
        try:
            _code, out, _err = _run_cli([path])
            self.assertIn("LIC-005", out)
            self.assertIn("summary:", out)
        finally:
            os.remove(path)

    def test_json_output_is_valid_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(WARN_ONLY, f)
            path = f.name
        try:
            _code, out, _err = _run_cli(["--json", path])
            data = json.loads(out)
            self.assertIn("findings", data)
            self.assertIn("summary", data)
            self.assertGreaterEqual(data["summary"]["total"], 1)
        finally:
            os.remove(path)


class InputModeTests(unittest.TestCase):

    def test_stdin_input(self):
        code, out, _err = _run_cli(["-"], stdin_text=json.dumps(CLEAN))
        self.assertEqual(code, 0)
        self.assertIn("no findings", out)

    def test_stdin_is_default_when_no_arg(self):
        code, _out, _err = _run_cli([], stdin_text=json.dumps(CLEAN))
        self.assertEqual(code, 0)

    def test_missing_file_prints_to_stderr_and_exits_two(self):
        code, _out, err = _run_cli(["/no/such/manifest.json"])
        self.assertEqual(code, 2)
        self.assertIn("manifest", err.lower())


class IncludeInfoTests(unittest.TestCase):

    def test_info_hidden_by_default(self):
        orphans = {
            "version": 1,
            "chain": [
                {"name": "a", "role": "model", "license": "MIT"},
                {"name": "b", "role": "model", "license": "MIT"},
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(orphans, f)
            path = f.name
        try:
            code, out, _err = _run_cli([path])
            self.assertEqual(code, 0)
            self.assertNotIn("LIC-012", out)
        finally:
            os.remove(path)

    def test_include_info_surfaces_lic012(self):
        orphans = {
            "version": 1,
            "chain": [
                {"name": "a", "role": "model", "license": "MIT"},
                {"name": "b", "role": "model", "license": "MIT"},
            ],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(orphans, f)
            path = f.name
        try:
            _code, out, _err = _run_cli(["--include-info", path])
            self.assertIn("LIC-012", out)
        finally:
            os.remove(path)


class VersionTests(unittest.TestCase):

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            _run_cli(["--version"])
        # argparse exits 0 for --version.
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
