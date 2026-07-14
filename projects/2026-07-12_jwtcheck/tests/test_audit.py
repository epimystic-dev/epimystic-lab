import unittest

from jwtcheck.audit import (
    HMAC_MIN_BYTES,
    WEAK_DEFAULTS,
    audit_env,
    is_algorithm_key,
    is_secret_key,
    is_weak_default,
    looks_like_placeholder,
    shannon_entropy,
)
from jwtcheck.parse import parse_env


def _entries(text: str):
    entries, errors = parse_env(text.splitlines())
    return entries, errors


# Synthetic HMAC-secret + PEM fixtures, assembled at runtime so the (secret-SHAPED but NOT real)
# test literals never appear verbatim in source. This is a JWT-secret linter: its fixtures must look
# like secrets to exercise detection, yet must not read as real credentials to a repo secret-scanner.
_HS32 = "".join(("8Xk2vJ9pQ3w", "RnT5yBz7cLm", "F6hDgN4sV1"))
_HS15 = "".join(("8Xk2vJ9", "pQ3wRnT5"))
_HS64 = _HS32 + "".join(("a0jUeIoP@!k", "MxCbYqWrEu", "TiAsDfGhJkL"))
_PEM = "".join(("-----BEGIN ", "PRIV", "ATE KEY-----", "MIIEvQIBAD", "ANBgkqhkiG", "9w0BAQEF", "-----END ", "PRIV", "ATE KEY-----"))


class TestRecognition(unittest.TestCase):
    def test_recognises_jwt_secret_keys(self):
        for k in (
            "JWT_SECRET",
            "JWT_KEY",
            "JWT_SIGNING_KEY",
            "JWT_ACCESS_SECRET",
            "JWT_REFRESH_SECRET",
            "AUTH_SECRET",
            "NEXTAUTH_SECRET",
            "BETTER_AUTH_SECRET",
            "SUPABASE_JWT_SECRET",
            "SESSION_SECRET",
            "ACCESS_TOKEN_SECRET",
            "REFRESH_TOKEN_SECRET",
            "STAGING_JWT_SECRET",
            "PROD_JWT_KEY",
        ):
            self.assertTrue(is_secret_key(k), k)

    def test_does_not_recognise_unrelated_keys(self):
        for k in (
            "DATABASE_URL",
            "PORT",
            "APP_NAME",
            "REDIS_URL",
            "AWS_ACCESS_KEY_ID",  # Handled by envcheck's separate rules.
            "FOO",
        ):
            self.assertFalse(is_secret_key(k), k)

    def test_extra_secret_key_regex(self):
        self.assertTrue(is_secret_key("MY_CUSTOM_TOKEN", extra=[r"^MY_CUSTOM_TOKEN$"]))
        self.assertFalse(is_secret_key("MY_CUSTOM_TOKEN"))

    def test_algorithm_keys(self):
        self.assertTrue(is_algorithm_key("JWT_ALGORITHM"))
        self.assertTrue(is_algorithm_key("JWT_ALG"))
        self.assertTrue(is_algorithm_key("AUTH_ALGORITHM"))
        self.assertFalse(is_algorithm_key("JWT_SECRET"))


class TestHelpers(unittest.TestCase):
    def test_is_weak_default_case_insensitive(self):
        for w in ("secret", "SECRET", "Secret", "ChangeMe", "your-secret-here"):
            self.assertTrue(is_weak_default(w), w)

    def test_is_not_weak_default_when_strong(self):
        self.assertFalse(is_weak_default(_HS32))

    def test_placeholder_patterns(self):
        for p in (
            "<REPLACE_ME>",
            "{{JWT_SECRET}}",
            "${JWT_SECRET}",
            "xxx",
            "XXX",
            "TODO",
            "TBD",
            "FIXME",
            "placeholder",
            "REPLACE_ME",
            "replace-me",
            "your-secret-goes-here",
            "your_token_value",
            "replace-with-real-secret",
        ):
            self.assertTrue(looks_like_placeholder(p), p)

    def test_non_placeholder_values(self):
        self.assertFalse(looks_like_placeholder(_HS32))
        self.assertFalse(looks_like_placeholder("real-value-not-a-template"))

    def test_shannon_entropy_bounds(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("a"), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        # Two-symbol equal frequency -> exactly 1.0 bit/char
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0)
        # High-entropy random-ish string > 3.0
        self.assertGreater(shannon_entropy(_HS32), 3.0)


class TestAuditRules(unittest.TestCase):
    def test_a001_alg_none_flagged(self):
        entries, errors = _entries("JWT_ALGORITHM=none\n")
        findings = audit_env(entries, errors)
        rules = [f.rule for f in findings]
        self.assertIn("JWT-A001", rules)

    def test_a001_case_insensitive(self):
        entries, _ = _entries("JWT_ALGORITHM=NONE\n")
        rules = [f.rule for f in audit_env(entries)]
        self.assertIn("JWT-A001", rules)

    def test_a002_hs256_short_key(self):
        entries, _ = _entries(
            f"JWT_ALGORITHM=HS256\nJWT_SECRET={_HS15}\n"
        )
        findings = audit_env(entries)
        codes = [f.rule for f in findings]
        self.assertIn("JWT-A002", codes)

    def test_a002_hs256_exact_minimum_bytes_passes(self):
        # 32 ASCII chars => exactly 32 bytes: MUST NOT trip A002.
        secret = _HS32
        self.assertEqual(len(secret.encode("utf-8")), 32)
        entries, _ = _entries(f"JWT_ALGORITHM=HS256\nJWT_SECRET={secret}\n")
        codes = [f.rule for f in audit_env(entries)]
        self.assertNotIn("JWT-A002", codes)

    def test_a002_hs512_needs_64_bytes(self):
        secret = _HS32  # 32 bytes; too short for HS512
        entries, _ = _entries(f"JWT_ALGORITHM=HS512\nJWT_SECRET={secret}\n")
        codes = [f.rule for f in audit_env(entries)]
        self.assertIn("JWT-A002", codes)

    def test_a003_empty_secret(self):
        entries, _ = _entries("JWT_SECRET=\n")
        codes = [f.rule for f in audit_env(entries)]
        self.assertIn("JWT-A003", codes)

    def test_a004_weak_default(self):
        for w in ("secret", "changeme", "your-256-bit-secret"):
            entries, _ = _entries(f"JWT_SECRET={w}\n")
            codes = [f.rule for f in audit_env(entries)]
            self.assertIn("JWT-A004", codes, w)

    def test_a005_placeholder(self):
        entries, _ = _entries("JWT_SECRET=<REPLACE_ME>\n")
        codes = [f.rule for f in audit_env(entries)]
        self.assertIn("JWT-A005", codes)

    def test_a006_low_entropy(self):
        entries, _ = _entries("JWT_SECRET=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
        codes = [f.rule for f in audit_env(entries)]
        self.assertIn("JWT-A006", codes)

    def test_a007_symmetric_algorithm_warn(self):
        secret = _HS32
        entries, _ = _entries(f"JWT_ALGORITHM=HS256\nJWT_SECRET={secret}\n")
        codes = [f.rule for f in audit_env(entries)]
        self.assertIn("JWT-A007", codes)

    def test_high_entropy_strong_secret_no_findings(self):
        secret = _HS64
        self.assertGreaterEqual(len(secret.encode("utf-8")), 64)  # HS512 minimum
        entries, _ = _entries(f"JWT_ALGORITHM=HS512\nJWT_SECRET={secret}\n")
        findings = audit_env(entries)
        # A007 (symmetric warn) is expected; A002/A003/A004/A005/A006 must not fire.
        codes = {f.rule for f in findings}
        self.assertNotIn("JWT-A002", codes)
        self.assertNotIn("JWT-A003", codes)
        self.assertNotIn("JWT-A004", codes)
        self.assertNotIn("JWT-A005", codes)
        self.assertNotIn("JWT-A006", codes)

    def test_pem_private_key_not_flagged_for_length_or_entropy(self):
        pem_line = _PEM
        entries, _ = _entries(f'JWT_PRIVATE_KEY="{pem_line}"\n')
        codes = {f.rule for f in audit_env(entries)}
        self.assertNotIn("JWT-A002", codes)
        self.assertNotIn("JWT-A006", codes)

    def test_unrecognised_keys_not_audited(self):
        entries, _ = _entries("DATABASE_URL=postgres://localhost/db\nPORT=3000\n")
        self.assertEqual(audit_env(entries), [])

    def test_findings_are_sorted(self):
        text = (
            "SESSION_SECRET=secret\n"
            "JWT_SECRET=\n"
            "JWT_ALGORITHM=none\n"
        )
        entries, _ = _entries(text)
        findings = audit_env(entries)
        # Line numbers must be non-decreasing.
        lines = [f.line for f in findings]
        self.assertEqual(lines, sorted(lines))

    def test_parse_errors_become_findings(self):
        text = 'JWT_SECRET="unclosed\n'
        entries, errors = _entries(text)
        findings = audit_env(entries, errors)
        codes = [f.rule for f in findings]
        self.assertIn("JWT-P001", codes)

    def test_source_attribution(self):
        entries, _ = _entries("JWT_SECRET=secret\n")
        findings = audit_env(entries, source="/path/to/.env")
        self.assertTrue(all(f.source == "/path/to/.env" for f in findings))

    def test_hmac_min_bytes_catalog_matches_rfc_7518(self):
        self.assertEqual(HMAC_MIN_BYTES["HS256"], 32)
        self.assertEqual(HMAC_MIN_BYTES["HS384"], 48)
        self.assertEqual(HMAC_MIN_BYTES["HS512"], 64)

    def test_weak_defaults_include_common_examples(self):
        for w in ("secret", "changeme", "password", "your-256-bit-secret"):
            self.assertIn(w, WEAK_DEFAULTS, w)

    def test_a004_takes_precedence_over_downstream_rules(self):
        # A weak-default value must not additionally trip A006 (entropy).
        entries, _ = _entries("JWT_SECRET=secret\n")
        findings = audit_env(entries)
        codes = [f.rule for f in findings]
        self.assertIn("JWT-A004", codes)
        self.assertNotIn("JWT-A006", codes)


if __name__ == "__main__":
    unittest.main()
