"""Parser-shape tests."""

from __future__ import annotations

import json
import unittest

from tests import support

from agentmemcheck.parse import (
    entry_content,
    entry_id,
    entry_reasoning,
    entry_role,
    entry_source,
    entry_ttl,
    load_text,
)


class ShapeTests(unittest.TestCase):
    def test_wrapper_memories(self):
        obj = {"schema_version": "1", "memories": [{"id": "a", "content": "x", "source": "u"}]}
        doc, meta, entries, err = load_text(
            json.dumps(obj), "x.json"
        )
        self.assertIsNone(err)
        self.assertEqual(meta.get("schema_version"), "1")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], "memories[0]")

    def test_wrapper_records(self):
        obj = {"records": [{"id": "a", "content": "x", "source": "u"}]}
        _doc, _meta, entries, err = load_text(
            json.dumps(obj), "x.json"
        )
        self.assertIsNone(err)
        self.assertEqual(entries[0][0], "records[0]")

    def test_bare_array(self):
        obj = [{"id": "a", "content": "x", "source": "u"}]
        _doc, meta, entries, err = load_text(
            json.dumps(obj), "x.json"
        )
        self.assertIsNone(err)
        self.assertEqual(meta, {})
        self.assertEqual(entries[0][0], "[0]")

    def test_single_entry_root(self):
        obj = {"id": "a", "content": "x", "source": "u"}
        _doc, _meta, entries, err = load_text(
            json.dumps(obj), "x.json"
        )
        self.assertIsNone(err)
        self.assertEqual(entries[0][0], "<root>")

    def test_jsonl(self):
        text = "\n".join([
            json.dumps({"id": "a", "content": "x", "source": "u"}),
            json.dumps({"id": "b", "content": "y", "source": "u"}),
        ])
        doc, meta, entries, err = load_text(text, "x.jsonl")
        self.assertIsNone(err)
        self.assertIsNone(doc)
        self.assertEqual(meta, {})
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0][0], "line[1]")
        self.assertEqual(entries[1][0], "line[2]")

    def test_jsonl_blank_lines_ignored(self):
        text = (
            json.dumps({"id": "a", "content": "x", "source": "u"})
            + "\n\n"
            + json.dumps({"id": "b", "content": "y", "source": "u"})
        )
        _doc, _meta, entries, err = load_text(text, "x.jsonl")
        self.assertIsNone(err)
        self.assertEqual(len(entries), 2)

    def test_invalid_json(self):
        _doc, _meta, entries, err = load_text("not json", "x.json")
        self.assertIsNotNone(err)
        self.assertEqual(entries, [])

    def test_jsonl_non_object_line(self):
        _doc, _meta, entries, err = load_text(
            '{"id":"a","content":"x","source":"u"}\n42\n', "x.jsonl",
        )
        self.assertIsNotNone(err)
        self.assertEqual(entries, [])


class FieldAccessorTests(unittest.TestCase):
    def test_entry_content_prefers_content(self):
        self.assertEqual(entry_content({"content": "a", "text": "b"}), "a")

    def test_entry_content_falls_back_to_text(self):
        self.assertEqual(entry_content({"text": "b"}), "b")

    def test_entry_content_missing(self):
        self.assertEqual(entry_content({}), "")

    def test_entry_source_from_root(self):
        self.assertEqual(entry_source({"source": "u"}), "u")

    def test_entry_source_from_metadata(self):
        self.assertEqual(
            entry_source({"metadata": {"origin": "web"}}),
            "web",
        )

    def test_entry_source_missing(self):
        self.assertIsNone(entry_source({"content": "x"}))

    def test_entry_role(self):
        self.assertEqual(entry_role({"role": "system"}), "system")
        self.assertIsNone(entry_role({"content": "x"}))

    def test_entry_id_prefers_id(self):
        self.assertEqual(entry_id({"id": "a"}, "fb"), "a")

    def test_entry_id_fallback(self):
        self.assertEqual(entry_id({}, "fb"), "fb")

    def test_entry_ttl_integer(self):
        self.assertEqual(entry_ttl({"ttl": 60}), 60)

    def test_entry_ttl_expires_at(self):
        self.assertEqual(
            entry_ttl({"expires_at": "2030-01-01T00:00:00Z"}),
            "2030-01-01T00:00:00Z",
        )

    def test_entry_reasoning_string(self):
        self.assertEqual(
            entry_reasoning({"reasoning": "because"}), "because",
        )

    def test_entry_reasoning_list(self):
        self.assertEqual(
            entry_reasoning({"reasoning": ["a", "b"]}), "a\nb",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
