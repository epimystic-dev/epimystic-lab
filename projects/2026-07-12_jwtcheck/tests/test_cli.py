import io
import json
import os
import tempfile
import unittest

from jwtcheck.__main__ import run

# Synthetic 32-char HMAC secret, assembled at runtime (secret-shaped test fixture, not a real key).
_HS32 = "".join(("8Xk2vJ9pQ3w", "RnT5yBz7cLm", "F6hDgN4sV1"))


class TestCLI(unittest.TestCase):
    def _write_tmp_env(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".env")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        self.addCleanup(os.remove, path)
        return path

    def test_exit_zero_on_clean_env(self):
        path = self._write_tmp_env("DATABASE_URL=postgres://x/y\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = run([path], stdout=stdout, stderr=stderr)
        self.assertEqual(rc, 0)

    def test_exit_two_on_errors(self):
        path = self._write_tmp_env(
            "JWT_ALGORITHM=none\nJWT_SECRET=changeme\n"
        )
        rc = run([path], stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(rc, 2)

    def test_exit_one_on_warns_only(self):
        # Symmetric warn (A007) without error-severity findings.
        secret = _HS32
        path = self._write_tmp_env(
            f"JWT_ALGORITHM=HS256\nJWT_SECRET={secret}\n"
        )
        rc = run([path], stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(rc, 1)

    def test_text_output_shape(self):
        path = self._write_tmp_env("JWT_SECRET=\n")
        stdout = io.StringIO()
        run([path, "--format", "text"], stdout=stdout, stderr=io.StringIO())
        line = stdout.getvalue().splitlines()[0]
        # Expected form: <src>:<line>:<col>: <severity>: <rule>: <msg>
        self.assertTrue(line.startswith(path + ":"))
        self.assertIn("error:", line)
        self.assertIn("JWT-A003", line)

    def test_json_output_shape(self):
        path = self._write_tmp_env("JWT_SECRET=\n")
        stdout = io.StringIO()
        rc = run([path, "--format", "json"], stdout=stdout, stderr=io.StringIO())
        self.assertEqual(rc, 2)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, list)
        self.assertGreaterEqual(len(payload), 1)
        rec = payload[0]
        for key in ("rule", "severity", "message", "key", "line", "col", "source"):
            self.assertIn(key, rec)

    def test_missing_file_reports_and_exits_two(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = run(["/nonexistent/path/.env"], stdout=stdout, stderr=stderr)
        self.assertEqual(rc, 2)
        self.assertIn("no such file", stderr.getvalue())

    def test_directory_path_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stdout, stderr = io.StringIO(), io.StringIO()
            rc = run([d], stdout=stdout, stderr=stderr)
            self.assertEqual(rc, 2)
            self.assertIn("is a directory", stderr.getvalue())

    def test_extra_secret_key_flag_extends_recognition(self):
        path = self._write_tmp_env("MY_CUSTOM_TOKEN=changeme\n")
        # Without the flag: not recognised, exit 0.
        rc = run([path], stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(rc, 0)
        # With the flag: recognised as a secret; weak default -> exit 2.
        rc = run(
            [path, "--extra-secret-key", r"^MY_CUSTOM_TOKEN$"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 2)

    def test_severity_filter_suppresses_warns_in_output(self):
        secret = _HS32
        path = self._write_tmp_env(
            f"JWT_ALGORITHM=HS256\nJWT_SECRET={secret}\n"
        )
        stdout = io.StringIO()
        rc = run(
            [path, "--severity", "error"],
            stdout=stdout,
            stderr=io.StringIO(),
        )
        # Warns still affect the exit code - that's the whole-file verdict -
        # but they should not appear in the emitted report.
        self.assertEqual(rc, 1)
        self.assertNotIn("JWT-A007", stdout.getvalue())

    def test_multiple_files(self):
        good = self._write_tmp_env("DATABASE_URL=postgres://x/y\n")
        bad = self._write_tmp_env("JWT_SECRET=changeme\n")
        rc = run([good, bad], stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(rc, 2)


class TestExtraSecretKeyRegexValidation(unittest.TestCase):
    """Regression: user-supplied bad regexes to --extra-secret-key must not
    escape as a `re.PatternError` traceback. They must be rejected by argparse
    with a clean error and SystemExit(2). Each subtest corresponds to a
    real crash observed against jwtcheck before the fix."""

    def _write_tmp_env(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".env")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        self.addCleanup(os.remove, path)
        return path

    def _assert_argparse_rejects(self, bad_regex: str) -> None:
        path = self._write_tmp_env("MY_TOKEN=changeme\n")
        stderr = io.StringIO()
        # argparse type= failures raise SystemExit(2). The important guarantee
        # is that re.PatternError does NOT escape.
        with self.assertRaises(SystemExit) as cm:
            run(
                [path, "--extra-secret-key", bad_regex],
                stdout=io.StringIO(),
                stderr=stderr,
            )
        self.assertEqual(cm.exception.code, 2)
        # argparse writes the error to real sys.stderr, not our injected one;
        # asserting on the exit-code + non-traceback behaviour is the load-
        # bearing contract.

    def test_unterminated_character_set_does_not_traceback(self):
        # Was: re.PatternError: unterminated character set at position 0
        self._assert_argparse_rejects("[")

    def test_unterminated_subpattern_does_not_traceback(self):
        # Was: re.PatternError: missing ), unterminated subpattern at position 0
        self._assert_argparse_rejects("(unclosed")

    def test_bad_escape_does_not_traceback(self):
        # Was: re.PatternError: bad escape \p at position 0
        self._assert_argparse_rejects(r"\p")

    def test_valid_regex_still_accepted(self):
        # Guardrail: the validator must not over-reject.
        path = self._write_tmp_env("MY_CUSTOM_TOKEN=changeme\n")
        rc = run(
            [path, "--extra-secret-key", r"^MY_CUSTOM_TOKEN$"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 2)  # recognised as secret + weak default


class JsonAliasFlag(unittest.TestCase):
    """`--json` is a boolean shortcut for `--format json`. Second convergence
    step (after envcheck 2026-08-13) toward the single flag name documented
    in docs/CONVENTIONS.md; before this change argparse would reject `--json`
    with SystemExit(2)."""

    def _write_tmp_env(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".env")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        self.addCleanup(os.remove, path)
        return path

    def test_json_alias_produces_json_array_on_findings(self):
        path = self._write_tmp_env("JWT_SECRET=\n")
        stdout = io.StringIO()
        rc = run([path, "--json"], stdout=stdout, stderr=io.StringIO())
        self.assertEqual(rc, 2)
        payload = json.loads(stdout.getvalue())
        self.assertIsInstance(payload, list)
        self.assertGreaterEqual(len(payload), 1)
        rules = {r["rule"] for r in payload}
        self.assertIn("JWT-A003", rules)

    def test_json_alias_clean_input_returns_zero_with_empty_array(self):
        path = self._write_tmp_env("DATABASE_URL=postgres://x/y\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        rc = run([path, "--json"], stdout=stdout, stderr=stderr)
        self.assertEqual(rc, 0)
        # jwtcheck's JSON shape is a single array (not NDJSON); clean input
        # emits `[]` per the shape documented in docs/CONVENTIONS.md. The
        # shape convergence is a separate open backlog item.
        self.assertEqual(json.loads(stdout.getvalue()), [])

    def test_json_alias_output_matches_format_json_byte_for_byte(self):
        path = self._write_tmp_env(
            "JWT_ALGORITHM=none\nJWT_SECRET=changeme\n"
        )
        buf_alias, buf_legacy = io.StringIO(), io.StringIO()
        rc_alias = run(
            [path, "--json"], stdout=buf_alias, stderr=io.StringIO()
        )
        rc_legacy = run(
            [path, "--format", "json"], stdout=buf_legacy, stderr=io.StringIO()
        )
        self.assertEqual(rc_alias, rc_legacy)
        self.assertEqual(buf_alias.getvalue(), buf_legacy.getvalue())

    def test_json_wins_when_conflicting_format_text_also_given(self):
        # `--json` is the more specific, targeted intent; when both flags
        # are given, JSON must win so `--json` is safe to pass through a
        # wrapper that also inherits a legacy `--format text` default.
        path = self._write_tmp_env("JWT_SECRET=\n")
        stdout = io.StringIO()
        rc = run(
            [path, "--json", "--format", "text"],
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(rc, 2)
        # Would raise if the text formatter had run (its lines start with
        # `<path>:<line>:<col>:` and are not valid JSON).
        json.loads(stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
