import unittest
from datetime import date

from agentmdlint.config import Config
from agentmdlint.parse import parse_document
from agentmdlint.rules import (
    ALL_RULES,
    RULE_REGISTRY,
    evaluate,
    rule_001_bloat_bytes,
    rule_002_bloat_instructions,
    rule_003_duplicate_instructions,
    rule_004_missing_rationale,
    rule_005_dead_heading,
    rule_006_drift_marker,
    rule_007_stale_timestamp,
    rule_008_contradiction,
    rule_009_no_purpose_header,
    rule_010_imperative_wall,
)
from agentmdlint.types import Severity


class TestRuleRegistry(unittest.TestCase):
    def test_all_ten_rules_registered(self):
        expected = {"AGENTMD-00" + str(i) for i in range(1, 10)} | {"AGENTMD-010"}
        self.assertEqual(set(RULE_REGISTRY.keys()), expected)

    def test_all_rules_have_descriptions(self):
        for rid, desc in RULE_REGISTRY.items():
            self.assertTrue(desc, rid + " missing description")


class TestRule001Bytes(unittest.TestCase):
    def test_under_soft_no_finding(self):
        cfg = Config(soft_bytes=100, hard_bytes=200)
        doc = parse_document("t.md", "a")
        self.assertEqual(rule_001_bloat_bytes(doc, cfg, 50), [])

    def test_over_soft_medium(self):
        cfg = Config(soft_bytes=100, hard_bytes=200)
        doc = parse_document("t.md", "a")
        fs = rule_001_bloat_bytes(doc, cfg, 150)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.MEDIUM)

    def test_over_hard_high(self):
        cfg = Config(soft_bytes=100, hard_bytes=200)
        doc = parse_document("t.md", "a")
        fs = rule_001_bloat_bytes(doc, cfg, 300)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.HIGH)


class TestRule002Instructions(unittest.TestCase):
    def test_under_cap_no_finding(self):
        cfg = Config(soft_instructions=5, hard_instructions=10)
        text = "\n".join(["You must A"] * 3) + "\n"
        doc = parse_document("t.md", text)
        self.assertEqual(rule_002_bloat_instructions(doc, cfg, 0), [])

    def test_over_soft_medium(self):
        cfg = Config(soft_instructions=5, hard_instructions=10)
        text = "\n".join(["You must item" + str(i) for i in range(7)]) + "\n"
        doc = parse_document("t.md", text)
        fs = rule_002_bloat_instructions(doc, cfg, 0)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.MEDIUM)

    def test_over_hard_high(self):
        cfg = Config(soft_instructions=5, hard_instructions=10)
        text = "\n".join(["You must item" + str(i) for i in range(15)]) + "\n"
        doc = parse_document("t.md", text)
        fs = rule_002_bloat_instructions(doc, cfg, 0)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.HIGH)


class TestRule003Duplicates(unittest.TestCase):
    def test_near_duplicate_flagged(self):
        cfg = Config(duplicate_threshold=0.7)
        text = (
            "You must use HTTPS for API calls.\n"
            "You must use HTTPS for API calls.\n"
        )
        doc = parse_document("t.md", text)
        fs = rule_003_duplicate_instructions(doc, cfg, 0)
        self.assertGreaterEqual(len(fs), 1)
        self.assertEqual(fs[0].rule_id, "AGENTMD-003")

    def test_distinct_not_flagged(self):
        cfg = Config(duplicate_threshold=0.85)
        text = (
            "You must use HTTPS.\n"
            "You should limit memory.\n"
        )
        doc = parse_document("t.md", text)
        self.assertEqual(rule_003_duplicate_instructions(doc, cfg, 0), [])

    def test_threshold_respected(self):
        # slight rephrasing
        text = (
            "You must use HTTPS for API calls in production.\n"
            "You must use HTTPS for API calls in the production environment.\n"
        )
        doc = parse_document("t.md", text)
        low_cfg = Config(duplicate_threshold=0.5)
        self.assertGreaterEqual(len(rule_003_duplicate_instructions(doc, low_cfg, 0)), 1)
        high_cfg = Config(duplicate_threshold=0.99)
        self.assertEqual(rule_003_duplicate_instructions(doc, high_cfg, 0), [])


class TestRule004MissingRationale(unittest.TestCase):
    def test_bare_imperative_flagged(self):
        doc = parse_document("t.md", "You must use HTTPS.\n")
        fs = rule_004_missing_rationale(doc, Config(), 0)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.INFO)

    def test_because_clean(self):
        doc = parse_document("t.md", "You must use HTTPS because plaintext leaks tokens.\n")
        self.assertEqual(rule_004_missing_rationale(doc, Config(), 0), [])

    def test_rationale_next_line_clean(self):
        text = (
            "You must use HTTPS.\n"
            "Why: plaintext leaks tokens across every proxy in the path.\n"
        )
        doc = parse_document("t.md", text)
        self.assertEqual(rule_004_missing_rationale(doc, Config(), 0), [])


class TestRule005DeadHeading(unittest.TestCase):
    def test_empty_section_flagged(self):
        text = "# Title\n\n## Sub\n\n## Real\n\nlots of real content here for the section\n"
        doc = parse_document("t.md", text)
        fs = rule_005_dead_heading(doc, Config(min_section_tokens=5), 0)
        self.assertGreaterEqual(len(fs), 1)
        self.assertTrue(any("Sub" in f.message for f in fs))

    def test_populated_section_not_flagged(self):
        text = "# Title\n\nsome nice descriptive body here for the top section that is not empty\n"
        doc = parse_document("t.md", text)
        fs = rule_005_dead_heading(doc, Config(min_section_tokens=5), 0)
        self.assertEqual(fs, [])


class TestRule006Drift(unittest.TestCase):
    def test_todo_flagged(self):
        doc = parse_document("t.md", "TODO: rewrite\n")
        fs = rule_006_drift_marker(doc, Config(), 0)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.MEDIUM)

    def test_no_marker_clean(self):
        doc = parse_document("t.md", "some prose without markers\n")
        self.assertEqual(rule_006_drift_marker(doc, Config(), 0), [])


class TestRule007Stale(unittest.TestCase):
    def test_stale_flagged(self):
        cfg = Config(stale_days=30, today=date(2026, 8, 16))
        doc = parse_document("t.md", "Amended 2024-01-01\n")
        fs = rule_007_stale_timestamp(doc, cfg, 0)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.MEDIUM)

    def test_recent_not_flagged(self):
        cfg = Config(stale_days=30, today=date(2026, 8, 16))
        doc = parse_document("t.md", "Amended 2026-08-10\n")
        self.assertEqual(rule_007_stale_timestamp(doc, cfg, 0), [])

    def test_future_ignored(self):
        cfg = Config(stale_days=30, today=date(2026, 8, 16))
        doc = parse_document("t.md", "Deadline 2027-01-01\n")
        self.assertEqual(rule_007_stale_timestamp(doc, cfg, 0), [])

    def test_invalid_date_ignored(self):
        cfg = Config(stale_days=1, today=date(2026, 8, 16))
        doc = parse_document("t.md", "Number 2020-13-40 is bogus\n")
        self.assertEqual(rule_007_stale_timestamp(doc, cfg, 0), [])


class TestRule008Contradiction(unittest.TestCase):
    def test_contradiction_flagged(self):
        text = (
            "You must always use tabs for indentation in the project.\n"
            "You should never use tabs for indentation in the project.\n"
        )
        doc = parse_document("t.md", text)
        fs = rule_008_contradiction(doc, Config(), 0)
        self.assertGreaterEqual(len(fs), 1)
        self.assertEqual(fs[0].severity, Severity.HIGH)

    def test_no_contradiction_when_polarity_same(self):
        text = (
            "You must use tabs for indentation.\n"
            "You should use tabs for indentation.\n"
        )
        doc = parse_document("t.md", text)
        self.assertEqual(rule_008_contradiction(doc, Config(), 0), [])

    def test_distinct_subjects_not_flagged(self):
        text = (
            "You must use HTTPS for calls.\n"
            "You must not disable telemetry.\n"
        )
        doc = parse_document("t.md", text)
        self.assertEqual(rule_008_contradiction(doc, Config(), 0), [])


class TestRule009NoPurposeHeader(unittest.TestCase):
    def test_missing_header_flagged(self):
        doc = parse_document("t.md", "just some prose with no heading\n")
        fs = rule_009_no_purpose_header(doc, Config(), 0)
        self.assertEqual(len(fs), 1)

    def test_header_without_prose_flagged(self):
        doc = parse_document("t.md", "# Title\n\n## Sub\n\nprose\n")
        fs = rule_009_no_purpose_header(doc, Config(), 0)
        self.assertEqual(len(fs), 1)

    def test_header_with_prose_clean(self):
        doc = parse_document("t.md", "# Title\n\nThis file documents the purpose of the agent.\n")
        self.assertEqual(rule_009_no_purpose_header(doc, Config(), 0), [])


class TestRule010ImperativeWall(unittest.TestCase):
    def test_wall_flagged(self):
        text = "\n".join(["You must item" + str(i) for i in range(8)]) + "\n"
        doc = parse_document("t.md", text)
        fs = rule_010_imperative_wall(doc, Config(wall_length=7), 0)
        self.assertGreaterEqual(len(fs), 1)

    def test_wall_broken_by_rationale(self):
        text = (
            "You must A because reason A applies here.\n"
            "You must B because reason B applies here.\n"
            "You must C because reason C applies here.\n"
            "You must D because reason D applies here.\n"
            "You must E because reason E applies here.\n"
            "You must F because reason F applies here.\n"
            "You must G because reason G applies here.\n"
            "You must H because reason H applies here.\n"
        )
        doc = parse_document("t.md", text)
        fs = rule_010_imperative_wall(doc, Config(wall_length=7), 0)
        self.assertEqual(fs, [])

    def test_no_wall_short_run(self):
        text = "\n".join(["You must item" + str(i) for i in range(3)]) + "\n"
        doc = parse_document("t.md", text)
        self.assertEqual(rule_010_imperative_wall(doc, Config(wall_length=7), 0), [])


class TestEvaluateComposite(unittest.TestCase):
    def test_all_rules_invoked(self):
        # dense fixture that triggers multiple rules
        text = (
            "just prose\n"  # 009 header missing
            "You must always use tabs in the project.\n"  # imperative
            "You must never use tabs in the project.\n"  # contradiction 008
            "TODO: fix this\n"  # 006
            "Amended 2020-01-01\n"  # 007 stale
        )
        cfg = Config(stale_days=30, today=date(2026, 8, 16))
        doc = parse_document("t.md", text)
        findings = evaluate(doc, cfg, len(text.encode("utf-8")))
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("AGENTMD-008", rule_ids)
        self.assertIn("AGENTMD-006", rule_ids)
        self.assertIn("AGENTMD-007", rule_ids)


if __name__ == "__main__":
    unittest.main()
