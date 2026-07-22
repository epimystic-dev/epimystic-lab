"""Parser tests for reqcheck."""

import unittest

from reqcheck.parser import parse_text


class BlanksAndCommentsTests(unittest.TestCase):
    def test_empty_file(self):
        pf = parse_text("")
        self.assertEqual(pf.lines, [])

    def test_only_blank_lines(self):
        pf = parse_text("\n   \n\t\n")
        self.assertEqual(len(pf.lines), 3)
        for line in pf.lines:
            self.assertEqual(line.kind, "blank")

    def test_full_line_comment(self):
        pf = parse_text("# this is a note\n")
        self.assertEqual(pf.lines[0].kind, "comment")

    def test_indented_comment(self):
        pf = parse_text("    # indented\n")
        self.assertEqual(pf.lines[0].kind, "comment")

    def test_bom_stripped(self):
        pf = parse_text("﻿foo==1.0\n")
        self.assertEqual(pf.lines[0].kind, "requirement")
        self.assertEqual(pf.lines[0].name, "foo")

    def test_crlf_line_endings(self):
        pf = parse_text("foo==1.0\r\nbar>=2.0\r\n")
        self.assertEqual(len(pf.lines), 2)
        self.assertEqual(pf.lines[0].name, "foo")
        self.assertEqual(pf.lines[1].name, "bar")


class SimpleRequirementTests(unittest.TestCase):
    def test_exact_pin(self):
        pf = parse_text("requests==2.31.0\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "requirement")
        self.assertEqual(line.name, "requests")
        self.assertEqual(line.raw_name, "requests")
        self.assertEqual(line.version_specs, ["==2.31.0"])

    def test_bare_name(self):
        pf = parse_text("requests\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "requirement")
        self.assertEqual(line.name, "requests")
        self.assertEqual(line.version_specs, [])

    def test_ge_spec(self):
        pf = parse_text("requests>=2.0\n")
        self.assertEqual(pf.lines[0].version_specs, [">=2.0"])

    def test_compound_spec(self):
        pf = parse_text("requests>=2.0,<3.0\n")
        self.assertEqual(pf.lines[0].version_specs, [">=2.0", "<3.0"])

    def test_arbitrary_equality(self):
        pf = parse_text("foo===1.0-alpha\n")
        self.assertEqual(pf.lines[0].version_specs, ["===1.0-alpha"])

    def test_pep503_canonicalization(self):
        pf = parse_text("Beautiful.Soup_4==4.12\n")
        line = pf.lines[0]
        self.assertEqual(line.raw_name, "Beautiful.Soup_4")
        self.assertEqual(line.name, "beautiful-soup-4")


class ExtrasAndMarkersTests(unittest.TestCase):
    def test_extras(self):
        pf = parse_text("uvicorn[standard]==0.30.0\n")
        line = pf.lines[0]
        self.assertEqual(line.extras, ["standard"])
        self.assertEqual(line.version_specs, ["==0.30.0"])

    def test_multiple_extras(self):
        pf = parse_text("uvicorn[standard,ssl]==0.30.0\n")
        self.assertEqual(pf.lines[0].extras, ["standard", "ssl"])

    def test_pep508_markers(self):
        pf = parse_text('foo==1.0; python_version >= "3.9"\n')
        line = pf.lines[0]
        self.assertEqual(line.name, "foo")
        self.assertEqual(line.version_specs, ["==1.0"])
        self.assertIn("python_version", line.markers)


class HashesTests(unittest.TestCase):
    def test_single_hash(self):
        pf = parse_text("foo==1.0 --hash=sha256:" + "a" * 64 + "\n")
        line = pf.lines[0]
        self.assertEqual(len(line.hashes), 1)
        self.assertTrue(line.hashes[0].startswith("sha256:"))
        self.assertTrue(pf.any_hash_line)

    def test_multiple_hashes(self):
        line_text = (
            "foo==1.0 "
            "--hash=sha256:" + "a" * 64 + " "
            "--hash=sha256:" + "b" * 64 + "\n"
        )
        pf = parse_text(line_text)
        self.assertEqual(len(pf.lines[0].hashes), 2)

    def test_require_hashes_option(self):
        pf = parse_text("--require-hashes\nfoo==1.0\n")
        self.assertTrue(pf.require_hashes)


class InlineCommentTests(unittest.TestCase):
    def test_inline_comment_after_spec(self):
        pf = parse_text("foo==1.0  # pin because\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "requirement")
        self.assertEqual(line.name, "foo")
        self.assertEqual(line.version_specs, ["==1.0"])

    def test_hash_fragment_in_url_not_treated_as_comment(self):
        pf = parse_text(
            "git+https://example.com/foo/bar.git@" + "a" * 40 + "#egg=bar\n"
        )
        line = pf.lines[0]
        self.assertEqual(line.kind, "requirement")
        self.assertEqual(line.vcs, "git")
        self.assertEqual(line.name, "bar")


class VcsAndUrlTests(unittest.TestCase):
    def test_git_url_with_commit_sha(self):
        sha = "a" * 40
        pf = parse_text(f"git+https://example.com/foo/bar.git@{sha}#egg=bar\n")
        line = pf.lines[0]
        self.assertEqual(line.vcs, "git")
        self.assertEqual(line.vcs_ref, sha)
        self.assertEqual(line.name, "bar")

    def test_git_url_with_branch(self):
        pf = parse_text("git+https://example.com/foo/bar.git@main#egg=bar\n")
        line = pf.lines[0]
        self.assertEqual(line.vcs, "git")
        self.assertEqual(line.vcs_ref, "main")

    def test_url_form_requirement(self):
        pf = parse_text("bar @ https://example.com/bar-1.0.tar.gz\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "requirement")
        self.assertEqual(line.name, "bar")
        self.assertEqual(line.url, "https://example.com/bar-1.0.tar.gz")

    def test_git_ssh_user_at_host_not_confused_with_ref(self):
        pf = parse_text("git+ssh://git@example.com/foo/bar.git#egg=bar\n")
        line = pf.lines[0]
        self.assertEqual(line.vcs, "git")
        # The user 'git' before host should NOT be extracted as a commit ref.
        # (In this URL there is no '@' after the first '/', so ref is None.)
        self.assertIsNone(line.vcs_ref)


class OptionLineTests(unittest.TestCase):
    def test_index_url(self):
        pf = parse_text("--index-url https://pypi.example.com/simple\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "option")
        self.assertEqual(line.option, "--index-url")
        self.assertEqual(line.option_value, "https://pypi.example.com/simple")

    def test_index_url_equals_form(self):
        pf = parse_text("--index-url=https://pypi.example.com/simple\n")
        line = pf.lines[0]
        self.assertEqual(line.option, "--index-url")
        self.assertEqual(line.option_value, "https://pypi.example.com/simple")

    def test_extra_index_url(self):
        pf = parse_text("--extra-index-url https://internal.example.com/py\n")
        self.assertEqual(pf.lines[0].option, "--extra-index-url")

    def test_trusted_host(self):
        pf = parse_text("--trusted-host internal.example.com\n")
        self.assertEqual(pf.lines[0].option, "--trusted-host")

    def test_include_line(self):
        pf = parse_text("-r other.txt\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "include")
        self.assertEqual(line.option, "-r")
        self.assertEqual(line.option_value, "other.txt")

    def test_constraint_line(self):
        pf = parse_text("-c constraints.txt\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "include")
        self.assertEqual(line.option, "-c")

    def test_editable_git_url(self):
        pf = parse_text("-e git+https://example.com/foo/bar.git#egg=bar\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "editable")
        self.assertEqual(line.vcs, "git")
        self.assertEqual(line.name, "bar")

    def test_editable_local_path(self):
        pf = parse_text("-e ./local-package\n")
        line = pf.lines[0]
        self.assertEqual(line.kind, "editable")
        self.assertIsNone(line.vcs)
        self.assertEqual(line.url, "./local-package")


class InvalidSyntaxTests(unittest.TestCase):
    def test_leading_bracket_is_invalid(self):
        pf = parse_text("[nonsense]\n")
        self.assertEqual(pf.lines[0].kind, "invalid")

    def test_junk_after_spec_is_invalid(self):
        pf = parse_text("foo==1.0 garbage\n")
        # 'garbage' after a valid spec should trip trailing-tokens error
        self.assertEqual(pf.lines[0].kind, "invalid")


if __name__ == "__main__":
    unittest.main()
