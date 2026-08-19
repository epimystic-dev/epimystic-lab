import unittest

from agentmdlint.parse import (
    jaccard,
    normalized_subject_tokens,
    parse_document,
    polarity_of,
    tokenize_for_similarity,
)


class TestHeadingParsing(unittest.TestCase):
    def test_headings_detected(self):
        doc = parse_document("t.md", "# Title\n\nsome text\n\n## Sub\n\nmore text\n")
        headings = [l for l in doc.lines if l.is_heading]
        self.assertEqual(len(headings), 2)
        self.assertEqual(headings[0].heading_level, 1)
        self.assertEqual(headings[0].heading_text, "Title")
        self.assertEqual(headings[1].heading_level, 2)
        self.assertEqual(headings[1].heading_text, "Sub")

    def test_sections_span_correctly(self):
        text = "# A\n\nalpha\n\n## B\n\nbeta\ngamma\n\n## C\n\ndelta\n"
        doc = parse_document("t.md", text)
        titled = [s for s in doc.sections if s.heading_text]
        self.assertEqual([s.heading_text for s in titled], ["A", "B", "C"])
        # B section contains beta+gamma
        b = next(s for s in titled if s.heading_text == "B")
        content_texts = [l.stripped for l in b.lines if not l.is_heading and not l.is_blank]
        self.assertEqual(content_texts, ["beta", "gamma"])

    def test_root_section_before_first_heading(self):
        text = "preamble one\npreamble two\n\n# Title\n\nbody\n"
        doc = parse_document("t.md", text)
        root = doc.sections[0]
        self.assertEqual(root.heading_level, 0)
        preamble = [l.stripped for l in root.lines if not l.is_blank]
        self.assertEqual(preamble, ["preamble one", "preamble two"])


class TestCodeFenceAwareness(unittest.TestCase):
    def test_lines_inside_backtick_fence_marked_in_code(self):
        text = "prose\n```\ncode line\n```\nafter\n"
        doc = parse_document("t.md", text)
        by_num = {l.number: l for l in doc.lines}
        self.assertTrue(by_num[3].in_code_block)
        self.assertFalse(by_num[5].in_code_block)

    def test_tilde_fence_also_toggles(self):
        text = "~~~\ncode line\n~~~\nafter\n"
        doc = parse_document("t.md", text)
        self.assertTrue(doc.lines[1].in_code_block)
        self.assertFalse(doc.lines[3].in_code_block)

    def test_imperative_inside_code_fence_is_not_flagged(self):
        text = "```\nyou must call foo\n```\nnormal text\n"
        doc = parse_document("t.md", text)
        # imperative in the code block should not classify as imperative
        self.assertEqual(len(doc.imperatives), 0)


class TestImperativeDetection(unittest.TestCase):
    def test_positive_modals_detected(self):
        for modal in ["must", "should", "always", "require", "ensure", "make sure"]:
            doc = parse_document("t.md", "You " + modal + " use HTTPS for all requests.\n")
            self.assertEqual(len(doc.imperatives), 1, "expected imperative for modal " + modal)

    def test_negative_modals_detected(self):
        for modal in ["must not", "should not", "never", "do not", "don't", "avoid"]:
            doc = parse_document("t.md", modal + " commit secrets to the repo.\n")
            self.assertEqual(len(doc.imperatives), 1, "expected imperative for modal " + modal)

    def test_no_modal_no_imperative(self):
        doc = parse_document("t.md", "This is a description of the workflow.\n")
        self.assertEqual(len(doc.imperatives), 0)

    def test_case_insensitive(self):
        doc = parse_document("t.md", "You MUST use HTTPS.\n")
        self.assertEqual(len(doc.imperatives), 1)

    def test_partial_word_does_not_match(self):
        # "must" inside "muster" or "mustard" must not fire
        doc = parse_document("t.md", "The mustard is on the counter.\n")
        self.assertEqual(len(doc.imperatives), 0)
        doc = parse_document("t.md", "Muster your resources.\n")
        self.assertEqual(len(doc.imperatives), 0)

    def test_list_item_imperative_detected(self):
        doc = parse_document("t.md", "- You must lint the code.\n")
        self.assertEqual(len(doc.imperatives), 1)


class TestRationaleDetection(unittest.TestCase):
    def test_because_marker(self):
        doc = parse_document("t.md", "You must use HTTPS because plaintext leaks tokens.\n")
        self.assertTrue(doc.imperatives[0].has_rationale)

    def test_rationale_colon(self):
        doc = parse_document("t.md", "You must use HTTPS. Rationale: plaintext leaks tokens.\n")
        self.assertTrue(doc.imperatives[0].has_rationale)

    def test_parenthetical_rationale(self):
        doc = parse_document("t.md", "You must use HTTPS (plaintext leaks tokens easily).\n")
        self.assertTrue(doc.imperatives[0].has_rationale)

    def test_no_rationale_when_none(self):
        doc = parse_document("t.md", "You must use HTTPS.\n")
        self.assertFalse(doc.imperatives[0].has_rationale)


class TestDriftMarker(unittest.TestCase):
    def test_todo_detected(self):
        doc = parse_document("t.md", "TODO: refactor this section\n")
        self.assertTrue(doc.lines[0].has_drift_marker)

    def test_multiple_markers(self):
        for marker in ["TODO", "FIXME", "XXX", "HACK", "TBD", "DEPRECATED"]:
            doc = parse_document("t.md", marker + ": something\n")
            self.assertTrue(doc.lines[0].has_drift_marker, "marker " + marker + " not detected")

    def test_case_sensitive_marker(self):
        doc = parse_document("t.md", "todo write the test\n")
        self.assertFalse(doc.lines[0].has_drift_marker)

    def test_marker_inside_word_does_not_match(self):
        doc = parse_document("t.md", "The XXXVI century was long ago.\n")
        # 'XXX' as substring of 'XXXVI' should not fire due to word boundary
        self.assertFalse(doc.lines[0].has_drift_marker)


class TestSimilarity(unittest.TestCase):
    def test_jaccard_identical(self):
        self.assertEqual(jaccard(["a", "b", "c"], ["a", "b", "c"]), 1.0)

    def test_jaccard_disjoint(self):
        self.assertEqual(jaccard(["a", "b"], ["c", "d"]), 0.0)

    def test_jaccard_empty(self):
        self.assertEqual(jaccard([], []), 0.0)
        self.assertEqual(jaccard(["a"], []), 0.0)

    def test_tokenize_filters_single_chars(self):
        self.assertEqual(tokenize_for_similarity("a bb ccc"), ["bb", "ccc"])


class TestPolarity(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(polarity_of("you must use https"), "positive")

    def test_negative(self):
        self.assertEqual(polarity_of("never commit secrets"), "negative")

    def test_no_modal(self):
        self.assertIsNone(polarity_of("this is prose"))

    def test_negative_wins_on_tie(self):
        # both must and never in one line -- treat as negative
        self.assertEqual(polarity_of("you must never commit secrets"), "negative")

    def test_do_not_negative(self):
        self.assertEqual(polarity_of("do not commit secrets"), "negative")


class TestSubjectNormalisation(unittest.TestCase):
    def test_strips_modals_and_stopwords(self):
        subj = normalized_subject_tokens("You must commit the secrets to the repo")
        self.assertNotIn("must", subj)
        self.assertNotIn("you", subj)
        self.assertNotIn("the", subj)
        self.assertIn("commit", subj)
        self.assertIn("secrets", subj)
        self.assertIn("repo", subj)

    def test_positive_negative_share_subject(self):
        a = normalized_subject_tokens("always commit the secrets to the repo")
        b = normalized_subject_tokens("never commit secrets to the repo")
        # subjects should overlap heavily
        self.assertEqual(a, b)


class TestBOM(unittest.TestCase):
    def test_bom_stripped(self):
        text = "﻿# Title\n\nprose\n"
        doc = parse_document("t.md", text)
        self.assertTrue(doc.lines[0].is_heading)


if __name__ == "__main__":
    unittest.main()
