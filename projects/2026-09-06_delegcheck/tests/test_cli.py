import io
import json
import os
import tempfile
import unittest

from delegcheck.cli import main


def _run(args):
    out = io.StringIO()
    err = io.StringIO()
    try:
        code = main(args, stdout=out, stderr=err)
    except SystemExit as e:
        code = int(getattr(e, "code", 1) or 0)
    return code, out.getvalue(), err.getvalue()


def _write(dirpath, name, content):
    p = os.path.join(dirpath, name)
    os.makedirs(os.path.dirname(p) or dirpath, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


class TestCLIVersion(unittest.TestCase):

    def test_version_exits_zero(self):
        code, out, err = _run(["--version"])
        self.assertEqual(code, 0)


class TestCLIListRules(unittest.TestCase):

    def test_prints_ten_lines(self):
        code, out, err = _run(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertEqual(len([l for l in out.splitlines() if l.startswith("DEL-")]), 10)


class TestCLIMissingPath(unittest.TestCase):

    def test_stderr_exit_2(self):
        code, out, err = _run(["/does/not/exist/anywhere"])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)


class TestCLIDirScans(unittest.TestCase):

    def _healthy_obj(self):
        return {
            "credentials": [{
                "name": "t", "type": "bearer", "value_ref": "vault://t",
                "scope": "read:issues", "expires_at": "2026-10-01",
            }],
            "tools": [{"name": "list", "principal": "w"}],
        }

    def test_healthy_dir_exit_0(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            _write(d, "a.json", json.dumps(self._healthy_obj(), indent=2))
            code, out, err = _run([d])
            self.assertEqual(code, 0, msg=out + "\n" + err)
            self.assertIn("verdict: healthy", out)

    def test_unhealthy_dir_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            obj = {"credentials": [{"name": "t", "type": "bearer", "scope": "*", "value_ref": "vault://t", "expires_at": "2026-10-01"}]}
            _write(d, "a.json", json.dumps(obj, indent=2))
            code, out, err = _run([d])
            self.assertEqual(code, 2)
            self.assertIn("verdict: unhealthy", out)

    def test_no_files_default_exit_1(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            _write(d, "README.md", "no json here")
            code, out, err = _run([d])
            self.assertEqual(code, 1)
            self.assertIn("verdict: unknown", out)

    def test_no_files_strict_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            _write(d, "README.md", "no json here")
            code, out, err = _run([d, "--strict"])
            self.assertEqual(code, 2)

    def test_json_flag_parseable(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            _write(d, "a.json", json.dumps({"authorization": {"mode": "llm"}}, indent=2))
            code, out, err = _run([d, "--json"])
            payload = json.loads(out)
            self.assertEqual(payload["verdict"], "unhealthy")

    def test_include_info(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            parts = ("a1B2c3D4e5F6g7H8", "i9J0k1L2m3N4o5P6", "Q7r8S9t0U1v2W3x4")
            long_token = "".join(parts)
            obj = {"credentials": [{"name": "t", "type": "bearer", "value": long_token, "scope": "read:x", "expires_at": "2026-10-01"}]}
            _write(d, "a.json", json.dumps(obj, indent=2))
            code_default, out_default, _ = _run([d])
            code_incl, out_incl, _ = _run([d, "--include-info"])
            self.assertIn("info=1", out_default)
            self.assertNotIn("DEL-010", out_default)
            self.assertIn("DEL-010", out_incl)

    def test_disable_flips_verdict(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            _write(d, "a.json", json.dumps({"authorization": {"mode": "llm"}}, indent=2))
            code_all, out_all, _ = _run([d])
            code_dis, out_dis, _ = _run([d, "--disable", "DEL-003"])
            self.assertEqual(code_all, 2)
            self.assertEqual(code_dis, 0)

    def test_max_files_zero_stderr_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            code, out, err = _run([d, "--max-files", "0"])
            self.assertEqual(code, 2)

    def test_max_bytes_zero_stderr_exit_2(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            code, out, err = _run([d, "--max-bytes", "0"])
            self.assertEqual(code, 2)

    def test_default_path_is_cwd(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            _write(d, "README.md", "no json")
            old = os.getcwd()
            os.chdir(d)
            try:
                code, out, err = _run([])
                self.assertIn("verdict: unknown", out)
            finally:
                os.chdir(old)

    def test_glob_extends_default(self):
        with tempfile.TemporaryDirectory(prefix="dc-") as d:
            _write(d, "a.mcp", json.dumps({"authorization": {"mode": "llm"}}))
            code_default, out_default, _ = _run([d])
            code_glob, out_glob, _ = _run([d, "--glob", "*.mcp"])
            self.assertIn("verdict: unknown", out_default)
            self.assertIn("verdict: unhealthy", out_glob)


if __name__ == "__main__":
    unittest.main()
