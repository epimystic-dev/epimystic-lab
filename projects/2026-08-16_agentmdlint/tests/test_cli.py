import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from agentmdlint.cli import main


class TempRepo:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="agentmdlint_cli_")

    def write(self, rel, content):
        full = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(full) or self.root, exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content.encode("utf-8"))
        return full

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def run_cli(argv):
    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        code = main(argv)
    return code, out_buf.getvalue(), err_buf.getvalue()


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.repo = TempRepo()

    def tearDown(self):
        self.repo.cleanup()

    def test_version_exit_zero(self):
        code, out, _ = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("agentmdlint", out)

    def test_missing_path_stderr_exit_two(self):
        code, _, err = run_cli([os.path.join(self.repo.root, "no_such")])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_no_files_default_exit_one(self):
        self.repo.write("README.md", "# nothing\n")
        code, out, _ = run_cli([self.repo.root])
        self.assertEqual(code, 1)
        self.assertIn("unknown", out)

    def test_no_files_strict_exit_two(self):
        self.repo.write("README.md", "# nothing\n")
        code, _, _ = run_cli([self.repo.root, "--strict"])
        self.assertEqual(code, 2)

    def test_healthy_file_exit_zero(self):
        self.repo.write(
            "AGENTS.md",
            "# Purpose\n\nThis file documents how the agent operates in the project, "
            "including rationale for every rule below.\n\n## Rules\n\n"
            "You must use HTTPS because plaintext leaks tokens.\n",
        )
        code, out, _ = run_cli([self.repo.root])
        self.assertEqual(code, 0)
        self.assertIn("healthy", out)

    def test_unhealthy_file_exit_two(self):
        self.repo.write(
            "AGENTS.md",
            "# Purpose\n\nOverview.\n\n"
            "You must always use tabs for indentation in the project.\n"
            "You should never use tabs for indentation in the project.\n",
        )
        code, _, _ = run_cli([self.repo.root])
        self.assertEqual(code, 2)

    def test_json_output_parseable(self):
        self.repo.write(
            "AGENTS.md",
            "# Purpose\n\nDoc.\n\nYou must use HTTPS.\n",
        )
        code, out, _ = run_cli([self.repo.root, "--json"])
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "agentmdlint")
        self.assertIn("verdict", payload)

    def test_single_file_path(self):
        f = self.repo.write("MY.md", "# Doc\n\nprose\n\nYou must use HTTPS.\n")
        code, out, _ = run_cli([f, "--include-info"])
        self.assertIn(f, out)

    def test_include_info_shows_info(self):
        self.repo.write(
            "AGENTS.md",
            "# Purpose\n\nDoc.\n\nYou must use HTTPS.\n",
        )
        _, out_no, _ = run_cli([self.repo.root])
        _, out_yes, _ = run_cli([self.repo.root, "--include-info"])
        self.assertNotIn("AGENTMD-004", out_no)
        self.assertIn("AGENTMD-004", out_yes)

    def test_default_path_is_cwd(self):
        cwd = os.getcwd()
        try:
            os.chdir(self.repo.root)
            self.repo.write("README.md", "# nothing\n")
            code, out, _ = run_cli([])
            self.assertEqual(code, 1)
            self.assertIn("unknown", out)
        finally:
            os.chdir(cwd)

    def test_custom_files_argument(self):
        self.repo.write("MY_INSTRUCTIONS.md", "# Purpose\n\nGuide.\n\nYou must use HTTPS.\n")
        code, out, _ = run_cli([self.repo.root, "--files", "MY_INSTRUCTIONS.md", "--include-info"])
        self.assertIn("MY_INSTRUCTIONS.md", out)

    def test_invalid_today_exit_two(self):
        self.repo.write("AGENTS.md", "# Purpose\n\nGuide.\n")
        code, _, err = run_cli([self.repo.root, "--today", "not-a-date"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
