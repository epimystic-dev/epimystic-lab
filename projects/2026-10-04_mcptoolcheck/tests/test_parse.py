"""Tests for the file-shape parser."""

from __future__ import annotations

import unittest

from mcptoolcheck.parse import (
    extract_tools,
    load_json,
    tool_annotations,
    tool_description,
    tool_input_schema,
    tool_name,
)


class LoadJsonTests(unittest.TestCase):
    def test_ok(self):
        doc, err = load_json('{"a": 1}')
        self.assertEqual(doc, {"a": 1})
        self.assertIsNone(err)

    def test_bad_reports_line_col(self):
        doc, err = load_json("{bad json}")
        self.assertIsNone(doc)
        self.assertIsNotNone(err)
        self.assertIn("line", err)
        self.assertIn("column", err)


class ExtractToolsTests(unittest.TestCase):
    def test_tools_list_wrapper(self):
        doc = {"tools": [
            {"name": "a", "description": "x"},
            {"name": "b", "description": "y"},
        ]}
        out = extract_tools(doc)
        self.assertEqual([p for p, _ in out], ["tools[0]", "tools[1]"])
        self.assertEqual(out[0][1]["name"], "a")

    def test_bare_array(self):
        doc = [{"name": "a", "description": "x"}]
        out = extract_tools(doc)
        self.assertEqual([p for p, _ in out], ["[0]"])

    def test_single_tool_object(self):
        doc = {"name": "a", "description": "x", "inputSchema": {}}
        out = extract_tools(doc)
        self.assertEqual([p for p, _ in out], ["<root>"])

    def test_dict_keyed_by_name_synthesises_name(self):
        doc = {
            "my_tool": {
                "description": "x",
                "inputSchema": {"type": "object"},
            }
        }
        out = extract_tools(doc)
        self.assertEqual([p for p, _ in out], ["my_tool"])
        # The name field is synthesised from the key when missing.
        self.assertEqual(out[0][1]["name"], "my_tool")

    def test_dict_keyed_tool_preserves_explicit_name(self):
        doc = {"a": {"name": "override", "description": "x",
                     "inputSchema": {}}}
        out = extract_tools(doc)
        self.assertEqual(out[0][1]["name"], "override")

    def test_non_tool_dict_is_empty(self):
        self.assertEqual(extract_tools({"something_else": 1}), [])

    def test_scalar_is_empty(self):
        self.assertEqual(extract_tools(42), [])
        self.assertEqual(extract_tools("x"), [])
        self.assertEqual(extract_tools(None), [])

    def test_tools_wrapper_skips_non_dict_entries(self):
        doc = {"tools": [
            {"name": "a", "description": "x"},
            "junk",
            42,
            {"name": "b", "description": "y"},
        ]}
        out = extract_tools(doc)
        self.assertEqual([p for p, _ in out], ["tools[0]", "tools[3]"])


class ToolFieldAccessorTests(unittest.TestCase):
    def test_tool_name_fallback(self):
        self.assertEqual(tool_name({}, "fb"), "fb")
        self.assertEqual(tool_name({"name": "n"}, "fb"), "n")
        self.assertEqual(tool_name({"name": ""}, "fb"), "fb")
        self.assertEqual(tool_name({"name": 42}, "fb"), "fb")

    def test_tool_description_default(self):
        self.assertEqual(tool_description({}), "")
        self.assertEqual(tool_description({"description": None}), "")
        self.assertEqual(tool_description({"description": "d"}), "d")

    def test_tool_input_schema_camel_or_snake(self):
        self.assertEqual(
            tool_input_schema({"inputSchema": {"type": "object"}}),
            {"type": "object"},
        )
        self.assertEqual(
            tool_input_schema({"input_schema": {"type": "object"}}),
            {"type": "object"},
        )
        self.assertIsNone(tool_input_schema({}))

    def test_tool_annotations_sibling_and_nested(self):
        self.assertEqual(
            tool_annotations({"annotations": {"readOnlyHint": True}}),
            {"readOnlyHint": True},
        )
        self.assertEqual(
            tool_annotations({"readOnlyHint": True}),
            {"readOnlyHint": True},
        )
        # Nested takes precedence when both appear.
        self.assertEqual(
            tool_annotations({
                "annotations": {"readOnlyHint": True},
                "readOnlyHint": False,
            })["readOnlyHint"],
            True,
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
