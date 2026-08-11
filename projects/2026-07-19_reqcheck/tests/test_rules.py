"""Rule-firing tests over parsed requirement fixtures."""

import unittest

from reqcheck.parser import parse_text
from reqcheck.rules import audit_parsed


def audit(text: str, include_info: bool = False):
    pf = parse_text(text, path="<fixture>")
    return audit_parsed(pf, include_info=include_info)


def rules_fired(text: str, include_info: bool = False):
    return sorted({f.rule for f in audit(text, include_info=include_info)})


class A001UnpinnedTests(unittest.TestCase):
    def test_ge_triggers(self):
        self.assertIn("REQ-A001", rules_fired("foo>=1.0\n"))

    def test_bare_triggers(self):
        self.assertIn("REQ-A001", rules_fired("foo\n"))

    def test_exact_pin_clean(self):
        self.assertNotIn("REQ-A001", rules_fired("foo==1.0\n"))

    def test_arbitrary_equality_clean(self):
        self.assertNotIn("REQ-A001", rules_fired("foo===1.0-alpha\n"))

    def test_wildcard_pin_still_unpinned(self):
        # '==1.0.*' is not an exact pin per PEP 440 - still unpinned for
        # reproducibility purposes.
        self.assertIn("REQ-A001", rules_fired("foo==1.0.*\n"))

    def test_url_form_not_flagged_by_a001(self):
        # URL/VCS pinning is A006's job.
        self.assertNotIn(
            "REQ-A001",
            rules_fired("git+https://example.com/foo/bar.git@" + "a" * 40 + "#egg=bar\n"),
        )


class A002HashMixTests(unittest.TestCase):
    def test_mixed_hash_discipline_triggers(self):
        text = (
            "foo==1.0 --hash=sha256:" + "a" * 64 + "\n"
            "bar==2.0\n"
        )
        rules = rules_fired(text)
        self.assertIn("REQ-A002", rules)

    def test_none_hashed_clean(self):
        text = "foo==1.0\nbar==2.0\n"
        self.assertNotIn("REQ-A002", rules_fired(text))

    def test_all_hashed_clean(self):
        text = (
            "foo==1.0 --hash=sha256:" + "a" * 64 + "\n"
            "bar==2.0 --hash=sha256:" + "b" * 64 + "\n"
        )
        self.assertNotIn("REQ-A002", rules_fired(text))

    def test_require_hashes_alone_fires_a002_for_unhashed(self):
        text = "--require-hashes\nfoo==1.0\n"
        self.assertIn("REQ-A002", rules_fired(text))


class A003TyposquatTests(unittest.TestCase):
    def test_requsts_triggers(self):
        rules = rules_fired("requsts==1.0\n")
        self.assertIn("REQ-A003", rules)

    def test_requests_clean(self):
        self.assertNotIn("REQ-A003", rules_fired("requests==1.0\n"))


class A004DuplicateTests(unittest.TestCase):
    def test_same_name_twice_triggers(self):
        text = "foo==1.0\nfoo==2.0\n"
        findings = audit(text)
        rules = [f.rule for f in findings]
        self.assertEqual(rules.count("REQ-A004"), 1)

    def test_case_and_punct_normalized(self):
        text = "Beautiful.Soup==4.0\nbeautiful-soup==4.1\n"
        rules = [f.rule for f in audit(text)]
        self.assertIn("REQ-A004", rules)

    def test_distinct_names_clean(self):
        self.assertNotIn("REQ-A004", rules_fired("foo==1.0\nbar==2.0\n"))


class A005TrustedHostTests(unittest.TestCase):
    def test_trusted_host_triggers_error(self):
        findings = audit("--trusted-host internal.example.com\n")
        rules = [(f.rule, f.severity) for f in findings]
        self.assertIn(("REQ-A005", "error"), rules)


class A006VcsTests(unittest.TestCase):
    def test_git_branch_ref_triggers(self):
        rules = rules_fired("git+https://example.com/foo/bar.git@main#egg=bar\n")
        self.assertIn("REQ-A006", rules)

    def test_git_sha_ref_clean(self):
        text = "git+https://example.com/foo/bar.git@" + "a" * 40 + "#egg=bar\n"
        self.assertNotIn("REQ-A006", rules_fired(text))

    def test_editable_vcs_branch_triggers(self):
        rules = rules_fired("-e git+https://example.com/foo/bar.git@main#egg=bar\n")
        self.assertIn("REQ-A006", rules)


class A007HomographTests(unittest.TestCase):
    def test_cyrillic_a_in_name_triggers(self):
        # Cyrillic 'а' (U+0430) - visually indistinguishable from Latin 'a'.
        text = "reqуests==1.0\n"
        rules = rules_fired(text)
        self.assertIn("REQ-A007", rules)

    def test_ascii_only_name_clean(self):
        self.assertNotIn("REQ-A007", rules_fired("requests==1.0\n"))


class A008EditableLocalTests(unittest.TestCase):
    def test_relative_path_triggers(self):
        rules = rules_fired("-e ./local\n")
        self.assertIn("REQ-A008", rules)

    def test_file_url_triggers(self):
        rules = rules_fired("-e file:///abs/path\n")
        self.assertIn("REQ-A008", rules)

    def test_vcs_editable_does_not_trigger_a008(self):
        text = "-e git+https://example.com/foo/bar.git@" + "a" * 40 + "#egg=bar\n"
        self.assertNotIn("REQ-A008", rules_fired(text))


class A009InfoTests(unittest.TestCase):
    def test_info_hidden_by_default(self):
        rules = rules_fired("--index-url https://pypi.example.com/simple\n")
        self.assertNotIn("REQ-A009", rules)

    def test_info_included_when_requested(self):
        rules = rules_fired(
            "--index-url https://pypi.example.com/simple\n", include_info=True
        )
        self.assertIn("REQ-A009", rules)


class OrderingAndFileFieldTests(unittest.TestCase):
    def test_findings_sorted_by_line_then_rule(self):
        text = "foo>=1.0\nbar>=1.0\n"
        findings = audit(text)
        lines = [(f.location.line, f.rule) for f in findings]
        self.assertEqual(lines, sorted(lines))

    def test_file_field_populated(self):
        text = "foo>=1.0\n"
        pf = parse_text(text, path="req.txt")
        findings = audit_parsed(pf)
        for f in findings:
            self.assertEqual(f.file, "req.txt")


if __name__ == "__main__":
    unittest.main()
