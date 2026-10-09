"""Rule-level tests: every rule has at least one positive and one
negative fixture, and every ID in REGISTRY appears in these tests."""

from __future__ import annotations

import unittest

from mcptoolcheck.rules import REGISTRY
from mcptoolcheck.types import Options, Severity

from tests import support
from tests.support import (
    bidi_char,
    build_doc,
    build_tool,
    control_char,
    homoglyph_word,
    pua_char,
    rule_ids,
    scan_dict,
    tag_char,
    zw_char,
)


class RegistryShapeTests(unittest.TestCase):
    def test_registry_is_non_empty_and_ac_prefixed(self):
        self.assertEqual(len(REGISTRY), 12)
        for r in REGISTRY:
            self.assertTrue(r.id.startswith("MTC-"), r.id)

    def test_registry_ids_are_contiguous_and_unique(self):
        ids = [r.id for r in REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))
        expected = ["MTC-%03d" % (i + 1) for i in range(12)]
        self.assertEqual(ids, expected)

    def test_severity_mix(self):
        c = {s: 0 for s in Severity}
        for r in REGISTRY:
            c[r.severity] += 1
        # 5 HIGH / 6 MEDIUM / 1 INFO documented in README.
        # HIGH: MTC-001, 002, 003, 006, 011.
        # MEDIUM: MTC-004, 005, 007, 008, 009, 010.
        # INFO: MTC-012.
        self.assertEqual(c[Severity.HIGH], 5)
        self.assertEqual(c[Severity.MEDIUM], 6)
        self.assertEqual(c[Severity.INFO], 1)


class MTC001TagBlockTests(unittest.TestCase):
    def test_fires_on_tag_in_description(self):
        tool = build_tool(
            description="Normal text" + tag_char() + " more text here"
        )
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-001", rule_ids(findings))

    def test_clean_description_does_not_fire(self):
        tool = build_tool(description="Perfectly normal ASCII text.")
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-001", rule_ids(findings))

    def test_reports_offset_and_codepoint(self):
        tool = build_tool(
            description="Hello" + tag_char() + " world and beyond"
        )
        _, findings = scan_dict(build_doc([tool]))
        hits = [f for f in findings if f.rule_id == "MTC-001"]
        self.assertEqual(len(hits), 1)
        self.assertIn("U+E0001", hits[0].message)
        self.assertIn("offset 5", hits[0].message)


class MTC002BidiTests(unittest.TestCase):
    def test_fires_on_bidi_override(self):
        tool = build_tool(
            description="read_file" + bidi_char() + "exe.txt (safe)"
        )
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-002", rule_ids(findings))

    def test_clean_does_not_fire(self):
        tool = build_tool(description="Plain description here")
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-002", rule_ids(findings))


class MTC003ZeroWidthTests(unittest.TestCase):
    def test_fires_on_zero_width(self):
        tool = build_tool(description="hello" + zw_char() + "world long enough")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-003", rule_ids(findings))

    def test_mid_string_bom_fires(self):
        tool = build_tool(description="hello" + zw_char(0xFEFF) + "world long")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-003", rule_ids(findings))

    def test_leading_bom_does_not_fire(self):
        tool = build_tool(description=zw_char(0xFEFF) + "hello world again")
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-003", rule_ids(findings))


class MTC004ControlTests(unittest.TestCase):
    def test_fires_on_control_char(self):
        tool = build_tool(description="hello" + control_char() + "world again")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-004", rule_ids(findings))

    def test_tab_newline_cr_do_not_fire(self):
        tool = build_tool(description="hello\tworld\nmore\rtext here")
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-004", rule_ids(findings))


class MTC005PuaTests(unittest.TestCase):
    def test_fires_on_pua(self):
        tool = build_tool(description="hello" + pua_char() + "world again")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-005", rule_ids(findings))

    def test_tag_block_is_not_PUA(self):
        # MTC-001 fires on TAG; MTC-005 explicitly excludes it so the
        # same character does not double-report.
        tool = build_tool(
            description="hello" + tag_char() + " world and beyond"
        )
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-001", rule_ids(findings))
        self.assertNotIn("MTC-005", rule_ids(findings))


class MTC006MissingPinTests(unittest.TestCase):
    def test_fires_when_no_pin(self):
        tool = build_tool()
        _, findings = scan_dict(build_doc([tool], pinned=False))
        self.assertIn("MTC-006", rule_ids(findings))

    def test_doc_level_pin_satisfies(self):
        tool = build_tool()
        _, findings = scan_dict(build_doc([tool], pinned=True))
        self.assertNotIn("MTC-006", rule_ids(findings))

    def test_tool_level_pin_satisfies(self):
        tool = build_tool(version="2026.10.04")
        doc = {"tools": [tool]}
        _, findings = scan_dict(doc)
        self.assertNotIn("MTC-006", rule_ids(findings))

    def test_empty_pin_does_not_satisfy(self):
        tool = build_tool()
        doc = {"tools": [tool], "version": ""}
        _, findings = scan_dict(doc)
        self.assertIn("MTC-006", rule_ids(findings))


class MTC007AnnotationMismatchTests(unittest.TestCase):
    def test_write_verb_with_readonly_fires(self):
        tool = build_tool(
            name="delete_record",
            description="Delete the record.",
            annotations={"readOnlyHint": True, "destructiveHint": False},
        )
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-007", rule_ids(findings))

    def test_read_verb_with_destructive_fires(self):
        tool = build_tool(
            name="list_files",
            description="List files in a directory.",
            annotations={"readOnlyHint": False, "destructiveHint": True},
        )
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-007", rule_ids(findings))

    def test_consistent_annotations_do_not_fire(self):
        tool = build_tool(
            name="read_file",
            annotations={"readOnlyHint": True, "destructiveHint": False},
        )
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-007", rule_ids(findings))

    def test_camelcase_name_is_tokenised(self):
        tool = build_tool(
            name="deleteRecord",
            annotations={"readOnlyHint": True, "destructiveHint": False},
        )
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-007", rule_ids(findings))


class MTC008MissingAnnotationsTests(unittest.TestCase):
    def test_no_annotations_fires(self):
        tool = build_tool(annotations=None)
        tool.pop("annotations", None)
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-008", rule_ids(findings))

    def test_present_annotations_do_not_fire(self):
        tool = build_tool()
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-008", rule_ids(findings))

    def test_sibling_annotation_satisfies(self):
        tool = build_tool()
        tool.pop("annotations", None)
        tool["readOnlyHint"] = True
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-008", rule_ids(findings))


class MTC009InputSchemaTests(unittest.TestCase):
    def test_missing_schema_fires(self):
        tool = build_tool()
        tool.pop("inputSchema", None)
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-009", rule_ids(findings))

    def test_additional_properties_true_fires(self):
        tool = build_tool(inputSchema={
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "additionalProperties": True,
        })
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-009", rule_ids(findings))

    def test_missing_type_fires(self):
        tool = build_tool(inputSchema={"properties": {}})
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-009", rule_ids(findings))

    def test_strict_schema_does_not_fire(self):
        tool = build_tool()
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-009", rule_ids(findings))


class MTC010HomoglyphTests(unittest.TestCase):
    def test_homoglyph_in_description_fires(self):
        tool = build_tool(description="Hello " + homoglyph_word() + " please")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-010", rule_ids(findings))

    def test_pure_latin_does_not_fire(self):
        tool = build_tool(description="Hello paypal from a latin word")
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-010", rule_ids(findings))

    def test_homoglyph_in_name_fires(self):
        tool = build_tool(name=homoglyph_word())
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-010", rule_ids(findings))


class MTC011NameHygieneTests(unittest.TestCase):
    def test_tag_in_name_fires(self):
        tool = build_tool(name="read" + tag_char() + "_file")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-011", rule_ids(findings))

    def test_zero_width_in_name_fires(self):
        tool = build_tool(name="read" + zw_char() + "_file")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-011", rule_ids(findings))

    def test_control_in_name_fires(self):
        tool = build_tool(name="read" + control_char() + "_file")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-011", rule_ids(findings))

    def test_bidi_in_name_fires(self):
        tool = build_tool(name="read" + bidi_char() + "_file")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-011", rule_ids(findings))

    def test_pua_in_name_fires(self):
        tool = build_tool(name="read" + pua_char() + "_file")
        _, findings = scan_dict(build_doc([tool]))
        self.assertIn("MTC-011", rule_ids(findings))

    def test_clean_name_does_not_fire(self):
        tool = build_tool(name="read_file_v2")
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-011", rule_ids(findings))


class MTC012LengthTests(unittest.TestCase):
    def test_empty_description_info_fires_under_strict(self):
        tool = build_tool(description="")
        _, findings = scan_dict(
            build_doc([tool]), options=Options(strict=True)
        )
        self.assertIn("MTC-012", rule_ids(findings))

    def test_short_description_info_fires_under_strict(self):
        tool = build_tool(description="too short")
        _, findings = scan_dict(
            build_doc([tool]), options=Options(strict=True)
        )
        self.assertIn("MTC-012", rule_ids(findings))

    def test_long_description_info_fires_under_strict(self):
        tool = build_tool(description="x " * 900 + "end.")
        _, findings = scan_dict(
            build_doc([tool]), options=Options(strict=True)
        )
        self.assertIn("MTC-012", rule_ids(findings))

    def test_info_hidden_by_default(self):
        tool = build_tool(description="")
        _, findings = scan_dict(build_doc([tool]))
        self.assertNotIn("MTC-012", rule_ids(findings))

    def test_info_visible_under_include_info(self):
        tool = build_tool(description="")
        _, findings = scan_dict(
            build_doc([tool]), options=Options(include_info=True)
        )
        self.assertIn("MTC-012", rule_ids(findings))


class RuleTogglingTests(unittest.TestCase):
    def test_only_filter(self):
        tool = build_tool(
            name="delete_record",
            annotations={"readOnlyHint": True, "destructiveHint": False},
            description="hello" + tag_char() + " more text here please",
        )
        _, findings = scan_dict(
            build_doc([tool]), options=Options(only=("MTC-001",))
        )
        self.assertEqual(rule_ids(findings), ("MTC-001",))

    def test_disable_suppresses_rule(self):
        tool = build_tool(
            description="hello" + tag_char() + " more text here please"
        )
        _, findings = scan_dict(
            build_doc([tool]), options=Options(disabled=("MTC-001",))
        )
        self.assertNotIn("MTC-001", rule_ids(findings))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
