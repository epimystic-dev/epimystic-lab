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
        # v0.2.0: on a rc=0 text-mode run the verdict-and-counts block
        # routes to stderr per docs/CONVENTIONS.md Stdout / stderr
        # discipline; stdout must be empty so downstream `jq` / `test -s`
        # CI wrappers can rely on empty stdout meaning "nothing to look
        # at". The rule-code content moved with it; on the dirty branch
        # (see test_unhealthy_file_exit_two-adjacent tests) it stays on
        # stdout.
        self.repo.write(
            "AGENTS.md",
            "# Purpose\n\nThis file documents how the agent operates in the project, "
            "including rationale for every rule below.\n\n## Rules\n\n"
            "You must use HTTPS because plaintext leaks tokens.\n",
        )
        code, out, err = run_cli([self.repo.root])
        self.assertEqual(code, 0)
        self.assertEqual(out, "", "stdout was: " + repr(out))
        self.assertIn("healthy", err)

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
        # v0.2.0: text-mode routing depends on the run's exit code
        # (stderr on rc=0, stdout otherwise). This test only asserts
        # that the scanned path shows up in the human-readable report,
        # not which stream carries it - the routing invariant is the
        # subject of test_shared_contract.py's new invariant test.
        f = self.repo.write("MY.md", "# Doc\n\nprose\n\nYou must use HTTPS.\n")
        code, out, err = run_cli([f, "--include-info"])
        combined = out if code != 0 else err
        self.assertIn(f, combined)

    def test_include_info_shows_info(self):
        # v0.2.0: both runs return rc=0 (HEALTHY - only INFO findings),
        # so the report body routes to stderr under the new discipline.
        # The behaviour under test is that --include-info surfaces
        # AGENTMD-004 in the report body; the assertion tracks the
        # report body wherever it lands.
        self.repo.write(
            "AGENTS.md",
            "# Purpose\n\nDoc.\n\nYou must use HTTPS.\n",
        )
        code_no, out_no, err_no = run_cli([self.repo.root])
        code_yes, out_yes, err_yes = run_cli([self.repo.root, "--include-info"])
        body_no = out_no if code_no != 0 else err_no
        body_yes = out_yes if code_yes != 0 else err_yes
        self.assertNotIn("AGENTMD-004", body_no)
        self.assertIn("AGENTMD-004", body_yes)

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
        # v0.2.0: --files causes MY_INSTRUCTIONS.md to be scanned; the
        # assertion tracks the report body wherever the exit-code-based
        # routing sends it.
        self.repo.write("MY_INSTRUCTIONS.md", "# Purpose\n\nGuide.\n\nYou must use HTTPS.\n")
        code, out, err = run_cli([self.repo.root, "--files", "MY_INSTRUCTIONS.md", "--include-info"])
        combined = out if code != 0 else err
        self.assertIn("MY_INSTRUCTIONS.md", combined)

    def test_invalid_today_exit_two(self):
        self.repo.write("AGENTS.md", "# Purpose\n\nGuide.\n")
        code, _, err = run_cli([self.repo.root, "--today", "not-a-date"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
