"""Tests for the regex pattern library.

These pin down the shape of each rule family so future tuning does not
silently regress coverage.
"""

import re
import unittest

from aicontribcheck import patterns


class BanPatternTests(unittest.TestCase):
    def _match(self, text: str) -> bool:
        return any(p.search(text) for p in patterns.pattern("ban"))

    def test_does_not_accept_ai_generated(self):
        self.assertTrue(
            self._match("This project does not accept AI-generated code.")
        )

    def test_we_will_not_merge_llm_output(self):
        self.assertTrue(
            self._match("We will not merge LLM-authored PRs at this time.")
        )

    def test_ai_contributions_are_banned(self):
        self.assertTrue(
            self._match("AI-generated contributions are banned in this repo.")
        )

    def test_no_ai_code(self):
        self.assertTrue(self._match("No AI-generated code, please."))

    def test_human_authored_only(self):
        self.assertTrue(self._match("Human-authored code only."))

    def test_ai_prs_will_be_rejected(self):
        self.assertTrue(
            self._match("AI-generated pull requests will be rejected.")
        )

    def test_agent_specific_ban(self):
        self.assertTrue(
            self._match("We do not accept coding-agent pull requests.")
        )

    def test_bare_ai_mention_does_not_trigger(self):
        self.assertFalse(self._match("We build AI systems here."))
        self.assertFalse(self._match("This project uses machine learning."))
        self.assertFalse(self._match("Great for AI research."))

    def test_no_documentation_style_mention(self):
        # A line like "See AI.md for context" must not trigger a ban.
        self.assertFalse(self._match("See AI.md for architectural context."))

    def test_case_insensitive(self):
        self.assertTrue(self._match("AI CONTRIBUTIONS ARE NOT ALLOWED."))


class AllowPatternTests(unittest.TestCase):
    def _match(self, text: str) -> bool:
        return any(p.search(text) for p in patterns.pattern("allow"))

    def test_ai_contributions_welcome(self):
        self.assertTrue(
            self._match("AI-generated contributions are welcome.")
        )

    def test_we_welcome_ai_assisted(self):
        self.assertTrue(
            self._match("We welcome AI-assisted pull requests here.")
        )

    def test_llm_authors_encouraged(self):
        self.assertTrue(
            self._match("LLM-authored contributions are encouraged.")
        )

    def test_bare_ai_mention_does_not_trigger(self):
        self.assertFalse(self._match("This project trains AI models."))


class DisclosurePatternTests(unittest.TestCase):
    def _match(self, text: str) -> bool:
        return any(p.search(text) for p in patterns.pattern("disclosure"))

    def test_must_be_disclosed(self):
        self.assertTrue(
            self._match(
                "AI-authored contributions must be disclosed in the PR body."
            )
        )

    def test_please_note_ai_usage(self):
        self.assertTrue(
            self._match("Please note if AI tools were used in this change.")
        )

    def test_co_authored_by_ai(self):
        self.assertTrue(
            self._match("Use a Co-Authored-By trailer naming the AI assistant.")
        )

    def test_should_be_declared(self):
        self.assertTrue(
            self._match("Generative AI usage should be declared explicitly.")
        )

    def test_no_disclosure_language(self):
        self.assertFalse(
            self._match("Please write clear commit messages.")
        )


class AttributionPatternTests(unittest.TestCase):
    def _match(self, text: str) -> bool:
        return any(p.search(text) for p in patterns.pattern("attribution"))

    def test_copyright_assignment(self):
        self.assertTrue(self._match("Contributors must assign copyright."))

    def test_dco(self):
        self.assertTrue(
            self._match("All commits must have a Developer Certificate of Origin.")
        )
        self.assertTrue(self._match("DCO required."))

    def test_cla(self):
        self.assertTrue(
            self._match("A signed Contributor License Agreement is required.")
        )
        self.assertTrue(self._match("CLA required."))

    def test_signed_off_by(self):
        self.assertTrue(self._match("All commits must be Signed-off-by."))

    def test_unrelated_line_does_not_trigger(self):
        self.assertFalse(self._match("The code is licensed under MIT."))


class ReviewPatternTests(unittest.TestCase):
    def _match(self, text: str) -> bool:
        return any(p.search(text) for p in patterns.pattern("review"))

    def test_human_review_required(self):
        self.assertTrue(self._match("Human review required for all PRs."))

    def test_requires_human_review(self):
        self.assertTrue(self._match("This project requires human review."))

    def test_four_eyes(self):
        self.assertTrue(self._match("Four-eyes review is mandatory here."))

    def test_unrelated(self):
        self.assertFalse(self._match("Automated linting will run in CI."))


class TestingPatternTests(unittest.TestCase):
    def _match(self, text: str) -> bool:
        return any(p.search(text) for p in patterns.pattern("testing"))

    def test_tests_required(self):
        self.assertTrue(self._match("Tests are required for all new code."))

    def test_must_include_tests(self):
        self.assertTrue(self._match("PRs must include tests."))

    def test_no_test_language(self):
        self.assertFalse(self._match("Please open an issue first."))


class ToolPatternTests(unittest.TestCase):
    """The shipped patterns name no vendor; product names are registered by the caller.

    These exercise that contract with neutral placeholder names, so the suite proves
    the extensibility mechanism rather than pinning one moment's product landscape.
    """

    SAMPLE_NAMES = ["acme-assistant", "helperbot", "codewright"]

    def setUp(self):
        patterns.clear_tool_names()

    def tearDown(self):
        patterns.clear_tool_names()

    def test_no_tool_names_by_default(self):
        # Ships vendor-neutral: nothing is recognised as a named product until registered.
        self.assertEqual(patterns.sources("tools"), [])
        self.assertEqual(patterns.registered_tool_names(), [])

    def test_registered_name_is_recognized(self):
        patterns.register_tool_names(self.SAMPLE_NAMES)
        for sample in self.SAMPLE_NAMES:
            hits = [p for p in patterns.pattern("tools") if p.search(f"Written with {sample}.")]
            self.assertTrue(hits, f"expected a tool pattern to match {sample!r} once registered")

    def test_registration_is_case_insensitive_and_deduped(self):
        patterns.register_tool_names(["Helperbot", "helperbot", "HELPERBOT"])
        self.assertEqual(len(patterns.registered_tool_names()), 1)
        hits = [p for p in patterns.pattern("tools") if p.search("used HelperBot here")]
        self.assertTrue(hits)

    def test_registered_name_extends_the_ban_marker(self):
        # A registered name must also satisfy the AI marker inside the verdict rules,
        # not merely the evidence rule -- otherwise "no <product> code" would not ban.
        patterns.register_tool_names(["helperbot"])
        hits = [p for p in patterns.pattern("ban") if p.search("We do not accept helperbot contributions.")]
        self.assertTrue(hits, "a registered name should count as an AI marker for ban detection")

    def test_bare_word_not_confused(self):
        # A registered name embedded in a longer word must not match on its own token.
        patterns.register_tool_names(["codex"])
        hits = [
            p
            for p in patterns.pattern("tools")
            if p.search("The codexample directory")
        ]
        self.assertEqual(hits, [])

    def test_name_with_regex_metacharacters_is_escaped(self):
        # Names are plain strings, not patterns: metacharacters must not blow up or over-match.
        patterns.register_tool_names(["c++helper"])
        self.assertTrue(any(p.search("built with c++helper") for p in patterns.pattern("tools")))
        self.assertFalse(any(p.search("built with chelper") for p in patterns.pattern("tools")))

    def test_clearing_removes_recognition(self):
        patterns.register_tool_names(["helperbot"])
        patterns.clear_tool_names()
        self.assertEqual(patterns.sources("tools"), [])
        self.assertFalse(any(p.search("helperbot") for p in patterns.pattern("tools")))


class SourcesTests(unittest.TestCase):
    def test_sources_return_list_of_strings(self):
        for kind in (
            "ban",
            "allow",
            "disclosure",
            "attribution",
            "review",
            "tools",
            "testing",
        ):
            srcs = patterns.sources(kind)
            self.assertIsInstance(srcs, list)
            self.assertTrue(all(isinstance(s, str) for s in srcs))
            if kind == "tools":
                # 'tools' ships EMPTY on purpose -- the linter names no vendor until the
                # caller registers names (see register_tool_names / --extra-tool-name).
                self.assertEqual(srcs, [], "shipped patterns must not hardcode product names")
            else:
                self.assertGreater(len(srcs), 0)

    def test_all_sources_compile_case_insensitive(self):
        for kind in (
            "ban",
            "allow",
            "disclosure",
            "attribution",
            "review",
            "tools",
            "testing",
        ):
            for src in patterns.sources(kind):
                # Should raise if any pattern is malformed.
                re.compile(src, re.IGNORECASE)


if __name__ == "__main__":
    unittest.main()
