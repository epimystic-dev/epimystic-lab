"""Drift, secret, and CheckOptions tests for envcheck."""

import unittest

from envcheck.core import CheckOptions, check, parse_bytes


def codes(diags):
    return [d.code for d in diags]


class DriftChecks(unittest.TestCase):
    def test_perfect_match_is_clean(self):
        t = parse_bytes(b"A=1\nB=2\n")
        e = parse_bytes(b"A=1\nB=2\n")
        self.assertEqual(check(t, e), [])

    def test_missing_key_in_env_is_D001(self):
        t = parse_bytes(b"A=1\nB=2\n")
        e = parse_bytes(b"A=1\n")
        d = check(t, e)
        self.assertIn("D001", codes(d))
        self.assertEqual([f.key for f in d if f.code == "D001"], ["B"])

    def test_extra_key_in_env_is_D002(self):
        t = parse_bytes(b"A=1\n")
        e = parse_bytes(b"A=1\nEXTRA=x\n")
        d = check(t, e)
        self.assertIn("D002", codes(d))
        self.assertEqual([f.key for f in d if f.code == "D002"], ["EXTRA"])

    def test_empty_env_where_template_has_example_is_D003(self):
        t = parse_bytes(b"API_HOST=https://example.com\n")
        e = parse_bytes(b"API_HOST=\n")
        d = check(t, e)
        self.assertIn("D003", codes(d))

    def test_empty_env_where_template_is_placeholder_is_clean(self):
        t = parse_bytes(b"API_KEY=changeme\n")
        e = parse_bytes(b"API_KEY=\n")
        self.assertNotIn("D003", codes(check(t, e)))

    def test_no_env_skips_drift(self):
        t = parse_bytes(b"A=1\n")
        self.assertEqual(check(t, None), [])

    def test_no_drift_option_skips_drift(self):
        t = parse_bytes(b"A=1\n")
        e = parse_bytes(b"A=1\nEXTRA=x\n")
        self.assertEqual(check(t, e, CheckOptions(drift=False, secrets=False)), [])


class SecretChecks(unittest.TestCase):
    def test_aws_access_key_pattern_flagged(self):
        t = parse_bytes(b"AWS_KEY=AKIA" + b"A" * 16 + b"\n")
        found = [d for d in check(t, None) if d.code == "S002"]
        self.assertEqual(len(found), 1)

    def test_google_api_key_flagged(self):
        val = b"AIza" + b"a" * 35
        t = parse_bytes(b"GOOGLE_KEY=" + val + b"\n")
        self.assertEqual(len([d for d in check(t, None) if d.code == "S002"]), 1)

    def test_sk_prefix_key_flagged(self):
        t = parse_bytes(b"KEY=sk-" + b"a" * 40 + b"\n")
        self.assertEqual(len([d for d in check(t, None) if d.code == "S002"]), 1)

    def test_github_pat_flagged(self):
        t = parse_bytes(b"GH_TOKEN=ghp_" + b"a" * 36 + b"\n")
        self.assertEqual(len([d for d in check(t, None) if d.code == "S002"]), 1)

    def test_private_key_blob_flagged(self):
        t = parse_bytes(
            b'PK="-----BEGIN RSA PRIV' b'ATE KEY-----"\n'
        )
        self.assertEqual(len([d for d in check(t, None) if d.code == "S002"]), 1)

    def test_placeholder_value_not_flagged(self):
        t = parse_bytes(b"API_KEY=changeme\n")
        self.assertEqual([d for d in check(t, None) if d.code == "S002"], [])

    def test_env_secret_uses_S001_code(self):
        e = parse_bytes(b"AWS_KEY=AKIA" + b"A" * 16 + b"\n")
        t = parse_bytes(b"AWS_KEY=changeme\n")
        found = [d for d in check(t, e) if d.code == "S001"]
        self.assertEqual(len(found), 1)

    def test_no_secrets_option_skips_secret_check(self):
        t = parse_bytes(b"AWS_KEY=AKIA" + b"A" * 16 + b"\n")
        d = check(t, None, CheckOptions(secrets=False))
        self.assertEqual([f for f in d if f.code.startswith("S")], [])


class MaxIssues(unittest.TestCase):
    def test_max_issues_truncates(self):
        t = parse_bytes(b"A=1\nB=2\nC=3\n")
        e = parse_bytes(b"X=1\nY=2\nZ=3\n")
        self.assertEqual(len(check(t, e, CheckOptions(max_issues=2))), 2)


if __name__ == "__main__":
    unittest.main()
