"""Parsing, position indexing, and the URI / host-layout shape helpers."""

from __future__ import annotations

import json
import unittest

from sarifcheck.parse import (
    PositionLookup,
    absolute_uri_shape,
    as_dict,
    as_list,
    build_index,
    build_position_index,
    count_threadflow_locations,
    decode_bytes,
    home_segment_shape,
    host_layout_matches,
    is_filesystem_absolute,
    iter_result_locations,
    load_json_document,
    location_artifact,
    nested_text,
    offset_to_line_col,
    short,
    strip_bom,
    token_shaped_runs,
    tokenize,
    uri_reference_defects,
    uri_scheme,
)

from tests.support import base_doc


class DecodeTests(unittest.TestCase):
    def test_plain_utf8(self):
        text, error = decode_bytes(b'{"a": 1}')
        self.assertIsNone(error)
        self.assertEqual(text, '{"a": 1}')

    def test_bom_is_stripped(self):
        text, error = decode_bytes(b"\xef\xbb\xbf{}")
        self.assertIsNone(error)
        self.assertEqual(text, "{}")

    def test_non_utf8_reports_the_byte_offset(self):
        text, error = decode_bytes(b'{"a": "\xff\xfe_not_utf8"}')
        self.assertIsNone(text)
        self.assertIn("not valid UTF-8", error)

    def test_utf16_bom_is_named(self):
        text, error = decode_bytes(b"\xff\xfe{\x00}\x00")
        self.assertIsNone(text)
        self.assertIn("UTF-16", error)

    def test_unicode_content_round_trips(self):
        text, error = decode_bytes('{"a": "\u00e9\u4e2d"}'.encode("utf-8"))
        self.assertIsNone(error)
        self.assertIn("\u4e2d", text)

    def test_strip_bom_is_a_noop_without_bom(self):
        self.assertEqual(strip_bom("abc"), "abc")


class LoadJsonTests(unittest.TestCase):
    def test_valid_object(self):
        doc, error, duplicates = load_json_document('{"a": 1}')
        self.assertIsNone(error)
        self.assertEqual(doc, {"a": 1})
        self.assertEqual(duplicates, [])

    def test_syntax_error_reports_line_and_column(self):
        doc, error, _ = load_json_document('{\n  "a": 1,\n  "b" 2\n}')
        self.assertIsNone(doc)
        self.assertIn("line 3", error)
        self.assertIn("column", error)

    def test_not_json_at_all(self):
        doc, error, _ = load_json_document("this is not json")
        self.assertIsNone(doc)
        self.assertIn("invalid JSON", error)

    def test_empty_input(self):
        doc, error, _ = load_json_document("")
        self.assertIsNone(doc)
        self.assertIn("invalid JSON", error)

    def test_duplicate_keys_are_reported_and_last_wins(self):
        doc, error, duplicates = load_json_document('{"a": 1, "a": 2}')
        self.assertIsNone(error)
        self.assertEqual(doc, {"a": 2})
        self.assertEqual(duplicates, ["a"])

    def test_deeply_nested_input_does_not_raise(self):
        depth = 20000
        text = "[" * depth + "]" * depth
        doc, error, _ = load_json_document(text)
        self.assertIsNone(doc)
        self.assertIsNotNone(error)

    def test_top_level_array_parses(self):
        doc, error, _ = load_json_document("[1, 2]")
        self.assertIsNone(error)
        self.assertEqual(doc, [1, 2])

    def test_null_byte_in_string_is_a_syntax_error(self):
        doc, error, _ = load_json_document('{"a": "b\x00c"}')
        self.assertIsNone(doc)
        self.assertIn("invalid JSON", error)


class TokenizerTests(unittest.TestCase):
    def test_tokenizes_structure(self):
        kinds = [kind for kind, _, _ in tokenize('{"a": [1, 2]}')]
        self.assertEqual(kinds, ["{", "str", ":", "[", "lit", ",", "lit", "]", "}"])

    def test_string_value_is_unescaped_enough_for_keys(self):
        tokens = tokenize('{"a\\"b": 1}')
        self.assertEqual(tokens[1][2], 'a"b')

    def test_token_cap_truncates(self):
        tokens = tokenize('[1, 2, 3, 4, 5]', max_tokens=3)
        self.assertEqual(len(tokens), 3)

    def test_empty_text(self):
        self.assertEqual(tokenize(""), [])


class PositionIndexTests(unittest.TestCase):
    def test_top_level_key(self):
        text = '{\n  "version": "2.1.0"\n}'
        index = build_position_index(text)
        self.assertIn("version", index)
        line, column = offset_to_line_col(text, index["version"])
        self.assertEqual(line, 2)

    def test_nested_array_path(self):
        text = json.dumps({"runs": [{"results": [{"message": {"text": "x"}}]}]}, indent=2)
        index = build_position_index(text)
        self.assertIn("runs[0].results[0].message.text", index)

    def test_second_array_element_has_its_own_path(self):
        text = json.dumps({"runs": [{"a": 1}, {"a": 2}]}, indent=2)
        index = build_position_index(text)
        self.assertIn("runs[0].a", index)
        self.assertIn("runs[1].a", index)
        self.assertNotEqual(index["runs[0].a"], index["runs[1].a"])

    def test_empty_array_does_not_break_the_walk(self):
        text = json.dumps({"runs": [], "version": "2.1.0"}, indent=2)
        index = build_position_index(text)
        self.assertIn("version", index)

    def test_empty_object_does_not_break_the_walk(self):
        text = json.dumps({"a": {}, "b": 1}, indent=2)
        index = build_position_index(text)
        self.assertIn("b", index)

    def test_lookup_returns_one_one_for_unknown_path(self):
        lookup = PositionLookup('{"a": 1}')
        self.assertEqual(lookup.locate("nope.nope"), (1, 1))

    def test_lookup_finds_a_known_path(self):
        lookup = PositionLookup('{\n"a": 1}')
        self.assertEqual(lookup.locate("a")[0], 2)

    def test_offset_to_line_col_first_line(self):
        self.assertEqual(offset_to_line_col("abc", 1), (1, 2))

    def test_offset_to_line_col_clamps(self):
        self.assertEqual(offset_to_line_col("abc", -5), (1, 1))
        self.assertEqual(offset_to_line_col("abc", 99), (1, 4))


class UriShapeTests(unittest.TestCase):
    def test_relative_uri_has_no_shape(self):
        self.assertEqual(absolute_uri_shape("src/a.py"), "")
        self.assertFalse(is_filesystem_absolute("src/a.py"))

    def test_posix_absolute(self):
        self.assertEqual(absolute_uri_shape("/build/a.py"), "posix-absolute")
        self.assertTrue(is_filesystem_absolute("/build/a.py"))

    def test_windows_drive(self):
        self.assertEqual(absolute_uri_shape("C:\\src\\a.py"), "windows-drive")
        self.assertEqual(absolute_uri_shape("C:/src/a.py"), "windows-drive")

    def test_file_uri_with_drive_is_windows_drive(self):
        self.assertEqual(absolute_uri_shape("file:///C:/src/a.py"), "windows-drive")

    def test_file_uri_without_drive(self):
        self.assertEqual(absolute_uri_shape("file:///build/a.py"), "file-scheme")

    def test_unc(self):
        self.assertEqual(absolute_uri_shape("\\\\server\\share\\a.py"), "unc")

    def test_http_is_network_not_filesystem(self):
        self.assertEqual(absolute_uri_shape("https://example.invalid/a"), "network-scheme")
        self.assertFalse(is_filesystem_absolute("https://example.invalid/a"))

    def test_uri_scheme_extraction(self):
        self.assertEqual(uri_scheme("FILE:///a"), "file")
        self.assertEqual(uri_scheme("src/a.py"), "")

    def test_empty_uri(self):
        self.assertEqual(absolute_uri_shape(""), "")
        self.assertEqual(absolute_uri_shape(None), "")


class UriReferenceDefectTests(unittest.TestCase):
    def test_clean_relative_uri_has_no_defects(self):
        self.assertEqual(uri_reference_defects("src/a.py"), [])

    def test_backslash_is_a_defect(self):
        names = [name for name, _ in uri_reference_defects("src\\a.py")]
        self.assertIn("backslash-separator", names)

    def test_unc_prefix_is_named_separately(self):
        names = [name for name, _ in uri_reference_defects("\\\\host\\share")]
        self.assertIn("unc-backslash-prefix", names)

    def test_raw_space_is_a_defect(self):
        names = [name for name, _ in uri_reference_defects("src/a b.py")]
        self.assertIn("unescaped-space", names)

    def test_percent_encoded_space_is_clean(self):
        self.assertEqual(uri_reference_defects("src/a%20b.py"), [])

    def test_control_character_is_a_defect(self):
        names = [name for name, _ in uri_reference_defects("src/a\tb.py")]
        self.assertIn("control-character", names)

    def test_offsets_are_reported(self):
        defects = dict(uri_reference_defects("src\\a.py"))
        self.assertEqual(defects["backslash-separator"], 3)


class HomeShapeTests(unittest.TestCase):
    def test_posix_home(self):
        shape = home_segment_shape("file:///home/devuser/src/a.py")
        self.assertIsNotNone(shape)
        self.assertEqual(shape[0], "posix-home")
        self.assertEqual(shape[2], len("devuser"))

    def test_macos_home(self):
        shape = home_segment_shape("/Users/devuser/src")
        self.assertEqual(shape[0], "macos-home")

    def test_windows_home(self):
        shape = home_segment_shape("C:\\Users\\devuser\\src")
        self.assertEqual(shape[0], "windows-home")

    def test_root_home(self):
        shape = home_segment_shape("/root/build")
        self.assertEqual(shape[0], "posix-root-home")

    def test_percent_encoded_home_is_decoded_first(self):
        shape = home_segment_shape("file:///home/dev%75ser/src")
        self.assertIsNotNone(shape)
        self.assertEqual(shape[0], "posix-home")

    def test_build_path_without_home_is_clean(self):
        self.assertIsNone(home_segment_shape("file:///build/workspace/src"))

    def test_homepage_word_is_not_a_home_segment(self):
        self.assertIsNone(home_segment_shape("https://example.invalid/homepage/x"))

    def test_empty_input(self):
        self.assertIsNone(home_segment_shape(""))
        self.assertIsNone(home_segment_shape(None))


class HostLayoutMatchTests(unittest.TestCase):
    def test_clean_message_has_no_matches(self):
        self.assertEqual(host_layout_matches("Unchecked return value on line 7."), [])

    def test_windows_drive_path_in_prose(self):
        matches = host_layout_matches("found in C:\\Users\\devuser\\a.py here")
        self.assertTrue(any(name == "windows-drive-path" for name, _, _ in matches))

    def test_posix_home_in_prose(self):
        matches = host_layout_matches("reads /home/devuser/.netrc at runtime")
        self.assertTrue(any(name == "posix-home" for name, _, _ in matches))

    def test_file_uri_in_prose(self):
        matches = host_layout_matches("see file:///build/out.log")
        self.assertTrue(any(name == "file-uri" for name, _, _ in matches))

    def test_relative_path_in_prose_is_not_matched(self):
        self.assertEqual(host_layout_matches("see src/widget/a.py line 4"), [])

    def test_matches_are_sorted_by_offset(self):
        matches = host_layout_matches("/Users/aa and /home/bb")
        offsets = [offset for _, offset, _ in matches]
        self.assertEqual(offsets, sorted(offsets))

    def test_offsets_index_the_original_string(self):
        text = "prefix /home/devuser/x"
        name, offset, length = host_layout_matches(text)[0]
        self.assertTrue(text[offset:offset + length].startswith("/home/"))


class TokenShapeTests(unittest.TestCase):
    def test_prose_is_not_token_shaped(self):
        self.assertEqual(token_shaped_runs("a short human readable message"), [])

    def test_long_mixed_run_is_token_shaped(self):
        value = "abcdefghij0123456789ABCDEFGHIJabcdefghij0123456789"
        found = token_shaped_runs("value " + value + " end")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][1], len(value))

    def test_all_digits_is_not_token_shaped(self):
        self.assertEqual(token_shaped_runs("1" * 60), [])

    def test_all_letters_is_not_token_shaped(self):
        self.assertEqual(token_shaped_runs("a" * 60), [])

    def test_low_distinct_run_is_not_token_shaped(self):
        self.assertEqual(token_shaped_runs("ab01" * 20), [])

    def test_short_run_is_not_token_shaped(self):
        self.assertEqual(token_shaped_runs("abc123XYZ"), [])


class HelperTests(unittest.TestCase):
    def test_as_dict_and_as_list_coerce(self):
        self.assertEqual(as_dict(None), {})
        self.assertEqual(as_dict([1]), {})
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list({"a": 1}), [])

    def test_nested_text_reads_two_layers(self):
        self.assertEqual(nested_text({"message": {"text": "x"}}, "message"), "x")
        self.assertIsNone(nested_text({"message": {}}, "message"))
        self.assertIsNone(nested_text({"message": "x"}, "message"))

    def test_short_collapses_newlines_and_truncates(self):
        self.assertEqual(short("a\nb"), "a b")
        self.assertTrue(short("x" * 400).endswith("..."))
        self.assertEqual(short(None), "")


class DocumentIndexTests(unittest.TestCase):
    def test_index_counts_driver_rules(self):
        index = build_index(base_doc())
        self.assertEqual(index.run_count, 1)
        self.assertEqual(index.runs[0].driver_rule_count, 1)
        self.assertTrue(index.runs[0].has_rule_metadata)

    def test_index_collects_extension_rules(self):
        doc = base_doc()
        doc["runs"][0]["tool"]["extensions"] = [
            {"name": "ext", "rules": [{"id": "EXT1"}, {"id": "EXT2"}]}
        ]
        index = build_index(doc)
        self.assertEqual(index.runs[0].extension_rule_count, 2)
        self.assertIn("EXT1", index.runs[0].rule_id_to_pos)

    def test_index_notes_external_property_files(self):
        doc = base_doc()
        doc["runs"][0]["externalPropertyFileReferences"] = {"results": []}
        index = build_index(doc)
        self.assertTrue(index.any_external_property_files)

    def test_index_of_a_non_sarif_object(self):
        index = build_index({"a": 1})
        self.assertEqual(index.run_count, 0)

    def test_index_tolerates_wrong_types(self):
        index = build_index({"runs": [{"tool": "not-an-object", "results": "nope"}]})
        self.assertEqual(index.runs[0].driver_rule_count, 0)
        self.assertEqual(index.runs[0].results, [])


class LocationWalkTests(unittest.TestCase):
    def test_walk_visits_locations(self):
        result = base_doc()["runs"][0]["results"][0]
        visited = iter_result_locations(result, "r")
        self.assertEqual(len(visited), 1)
        self.assertEqual(visited[0][0], "r.locations[0]")

    def test_walk_visits_related_locations(self):
        result = {"relatedLocations": [{"physicalLocation": {}}]}
        visited = iter_result_locations(result, "r")
        self.assertEqual(visited[0][0], "r.relatedLocations[0]")

    def test_walk_visits_analysis_target(self):
        result = {"analysisTarget": {"uri": "a.py"}}
        visited = iter_result_locations(result, "r")
        self.assertEqual(visited[0][0], "r.analysisTarget")
        artifact, _ = location_artifact(visited[0][1])
        self.assertEqual(artifact["uri"], "a.py")

    def test_walk_visits_thread_flow_locations(self):
        result = {
            "codeFlows": [
                {"threadFlows": [{"locations": [{"location": {"physicalLocation": {}}}]}]}
            ]
        }
        visited = iter_result_locations(result, "r")
        self.assertEqual(
            visited[0][0], "r.codeFlows[0].threadFlows[0].locations[0].location"
        )

    def test_walk_visits_fix_artifact_locations(self):
        result = {
            "fixes": [
                {"artifactChanges": [{"artifactLocation": {"uri": "a.py"}}]}
            ]
        }
        visited = iter_result_locations(result, "r")
        self.assertEqual(
            visited[0][0], "r.fixes[0].artifactChanges[0].artifactLocation"
        )

    def test_walk_is_empty_for_a_bare_result(self):
        self.assertEqual(iter_result_locations({}, "r"), [])

    def test_location_artifact_returns_none_when_absent(self):
        artifact, suffix = location_artifact({"physicalLocation": {}})
        self.assertIsNone(artifact)
        self.assertEqual(suffix, "")

    def test_threadflow_count_sums_across_all_code_flows(self):
        result = {
            "codeFlows": [
                {"threadFlows": [{"locations": [{}, {}]}]},
                {"threadFlows": [{"locations": [{}]}, {"locations": [{}, {}, {}]}]},
            ]
        }
        self.assertEqual(count_threadflow_locations(result), 6)

    def test_threadflow_count_of_a_bare_result(self):
        self.assertEqual(count_threadflow_locations({}), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
