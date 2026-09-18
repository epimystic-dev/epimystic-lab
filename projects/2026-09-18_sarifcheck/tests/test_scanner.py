"""Scanner behaviour: discovery, budgets, and adversarial input.

The contract under test is that no input shape produces a traceback. Every
one of them produces a structured diagnostic and a sane exit code.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from sarifcheck import limits as limits_mod
from sarifcheck.scanner import (
    DEFAULT_GLOBS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_FILES,
    build_options,
    compressed_size,
    discover,
    scan_file,
    scan_path,
)

from tests.support import ALL_PROFILES, base_doc, codes, fixture, scan_bytes, scan_text


def options(**kwargs):
    return build_options(
        limits=limits_mod.default_limits(),
        profiles=kwargs.pop("profiles", ALL_PROFILES),
        disabled=frozenset(kwargs.pop("disabled", ())),
    )


class DefaultsTests(unittest.TestCase):
    def test_default_globs_cover_both_sarif_spellings(self):
        self.assertIn("*.sarif", DEFAULT_GLOBS)
        self.assertIn("*.sarif.json", DEFAULT_GLOBS)

    def test_byte_budget_is_documented_and_finite(self):
        self.assertEqual(DEFAULT_MAX_BYTES, 64 * 1024 * 1024)

    def test_file_cap_is_finite(self):
        self.assertGreater(DEFAULT_MAX_FILES, 0)


class DiscoverTests(unittest.TestCase):
    def test_missing_path_discovers_nothing(self):
        self.assertEqual(discover(os.path.join(fixture("healthy"), "nope")), [])

    def test_explicit_file_is_scanned_whatever_its_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "results.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            self.assertEqual(discover(path), [path])

    def test_directory_walk_matches_the_globs(self):
        found = discover(fixture("healthy"))
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].endswith("results.sarif"))

    def test_directory_walk_ignores_non_sarif_files(self):
        self.assertEqual(discover(fixture("unknown")), [])

    def test_sarif_json_suffix_is_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "results.sarif.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            self.assertEqual(discover(tmp), [path])

    def test_glob_match_is_case_insensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "RESULTS.SARIF")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            self.assertEqual(len(discover(tmp)), 1)

    def test_custom_glob_extends_the_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "scan.out")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            self.assertEqual(discover(tmp), [])
            self.assertEqual(discover(tmp, globs=DEFAULT_GLOBS + ("*.out",)), [path])

    def test_max_files_caps_the_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            for n in range(5):
                with open(os.path.join(tmp, str(n) + ".sarif"), "w", encoding="utf-8") as handle:
                    handle.write("{}")
            self.assertEqual(len(discover(tmp, max_files=2)), 2)

    def test_walk_order_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("c.sarif", "a.sarif", "b.sarif"):
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as handle:
                    handle.write("{}")
            first = discover(tmp)
            second = discover(tmp)
            self.assertEqual(first, second)
            self.assertEqual([os.path.basename(p) for p in first],
                             ["a.sarif", "b.sarif", "c.sarif"])

    def test_nested_directories_are_walked(self):
        with tempfile.TemporaryDirectory() as tmp:
            inner = os.path.join(tmp, "inner")
            os.makedirs(inner)
            path = os.path.join(inner, "results.sarif")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            self.assertEqual(discover(tmp), [path])


class AdversarialInputTests(unittest.TestCase):
    def test_empty_file(self):
        result = scan_bytes(b"")
        self.assertTrue(result.errors)
        self.assertIn("invalid JSON", result.errors[0])

    def test_whitespace_only_file(self):
        result = scan_bytes(b"   \n\t  ")
        self.assertTrue(result.errors)

    def test_not_json_at_all(self):
        result = scan_bytes(b"<?xml version='1.0'?><results/>")
        self.assertTrue(result.errors)
        self.assertIn("invalid JSON", result.errors[0])

    def test_truncated_json(self):
        result = scan_bytes(b'{"version": "2.1.0", "runs": [')
        self.assertTrue(result.errors)

    def test_top_level_array(self):
        result = scan_bytes(b"[]")
        self.assertTrue(result.errors)
        self.assertIn("not an object", result.errors[0])

    def test_top_level_string(self):
        result = scan_bytes(b'"a sarif file"')
        self.assertTrue(result.errors)
        self.assertIn("not an object", result.errors[0])

    def test_top_level_number(self):
        result = scan_bytes(b"42")
        self.assertTrue(result.errors)

    def test_top_level_null(self):
        result = scan_bytes(b"null")
        self.assertTrue(result.errors)

    def test_object_without_runs(self):
        result = scan_bytes(b'{"version": "2.1.0"}')
        self.assertTrue(result.errors)
        self.assertIn("'runs'", result.errors[0])

    def test_null_bytes(self):
        result = scan_bytes(b'{"version": "2.1.0", "runs": [\x00]}')
        self.assertTrue(result.errors)

    def test_invalid_utf8(self):
        result = scan_bytes(b'{"version": "\xff\xfe"}')
        self.assertTrue(result.errors)
        self.assertIn("UTF-8", result.errors[0])

    def test_utf8_bom_is_tolerated(self):
        payload = json.dumps(base_doc()).encode("utf-8")
        result = scan_bytes(b"\xef\xbb\xbf" + payload)
        self.assertEqual(result.errors, ())
        self.assertEqual(codes(result), set())

    def test_deeply_nested_json(self):
        depth = 30000
        payload = ('{"version": "2.1.0", "runs": [{"x": ' + "[" * depth
                   + "]" * depth + "}]}")
        result = scan_text(payload)
        self.assertTrue(result.errors)
        self.assertEqual(result.findings, ())

    def test_huge_single_line(self):
        doc = base_doc()
        doc["runs"][0]["results"][0]["message"]["text"] = "x" * 500000
        result = scan_text(json.dumps(doc))
        self.assertEqual(result.errors, ())

    def test_unicode_content(self):
        doc = base_doc()
        doc["runs"][0]["results"][0]["message"]["text"] = "".join(chr(c) for c in (0x4e2d, 0x6587, 0x20, 0xe9, 0xe8, 0x20, 0x915))
        result = scan_text(json.dumps(doc, ensure_ascii=False))
        self.assertEqual(result.errors, ())
        self.assertEqual(codes(result), set())

    def test_duplicate_keys_are_noted_not_fatal(self):
        payload = (
            '{"version": "2.1.0", "version": "2.1.0", "runs": [], "runs": []}'
        )
        result = scan_text(payload)
        self.assertEqual(result.errors, ())
        self.assertTrue(result.notes)
        self.assertIn("duplicate", result.notes[0])

    def test_a_filename_that_looks_like_a_path_traversal(self):
        # The name is inert: sarifcheck opens exactly the path it was given.
        result = scan_text(json.dumps(base_doc()), filename="..evil..sarif")
        self.assertEqual(result.errors, ())

    def test_symlinked_file_is_read_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "real.sarif")
            with open(target, "w", encoding="utf-8") as handle:
                json.dump(base_doc(), handle)
            link = os.path.join(tmp, "link.sarif")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError, AttributeError):
                self.skipTest("symlink creation is not available here")
            found, errors, _notes, _partial = scan_file(link, options())
            self.assertEqual(errors, [])
            self.assertEqual(found, [])

    def test_unreadable_missing_file_is_an_error(self):
        found, errors, _notes, _partial = scan_file("no-such-file.sarif", options())
        self.assertEqual(found, [])
        self.assertTrue(errors)
        self.assertIn("read-error", errors[0])


class ByteBudgetTests(unittest.TestCase):
    def test_oversized_file_is_refused_not_parsed(self):
        result = scan_text(json.dumps(base_doc()), max_bytes=10)
        self.assertTrue(result.errors)
        self.assertIn("size-refused", result.errors[0])
        self.assertEqual(result.findings, ())

    def test_refusal_names_both_numbers(self):
        result = scan_text(json.dumps(base_doc()), max_bytes=10)
        self.assertIn("exceeds the --max-bytes budget of 10", result.errors[0])

    def test_file_under_the_budget_is_parsed(self):
        result = scan_text(json.dumps(base_doc()), max_bytes=10 * 1024 * 1024)
        self.assertEqual(result.errors, ())


class CompressedSizeTests(unittest.TestCase):
    def test_compressed_size_is_positive(self):
        self.assertGreater(compressed_size(b"abc"), 0)

    def test_repetitive_json_compresses_heavily(self):
        raw = (b'{"a": "value"}' * 4000)
        self.assertLess(compressed_size(raw), len(raw) // 10)

    def test_output_is_gzip_framed(self):
        blob_len = compressed_size(b"x" * 100)
        self.assertGreater(blob_len, 10)


class ScanPathTests(unittest.TestCase):
    def test_directory_scan_counts_files(self):
        result = scan_path(fixture("healthy"), options())
        self.assertEqual(result.files_scanned, 1)

    def test_empty_directory_scans_nothing(self):
        result = scan_path(fixture("unknown"), options())
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.findings, ())

    def test_findings_are_sorted_deterministically(self):
        result = scan_path(fixture("srf001_bad_version"), options())
        keys = [f.sort_key() for f in result.findings]
        self.assertEqual(keys, sorted(keys))

    def test_repeat_scans_are_identical(self):
        first = scan_path(fixture("srf004_absolute_uri"), options())
        second = scan_path(fixture("srf004_absolute_uri"), options())
        self.assertEqual(
            [(f.rule_id, f.prop, f.message) for f in first.findings],
            [(f.rule_id, f.prop, f.message) for f in second.findings],
        )

    def test_disabled_rule_is_not_applied(self):
        result = scan_path(
            fixture("srf001_bad_version"), options(disabled=("SRF-001",))
        )
        self.assertNotIn("SRF-001", codes(result))

    def test_multi_file_directory_aggregates(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.sarif", "b.sarif"):
                doc = base_doc()
                doc["version"] = "2.1"
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as handle:
                    json.dump(doc, handle)
            result = scan_path(tmp, options())
            self.assertEqual(result.files_scanned, 2)
            self.assertEqual(len(result.findings), 2)

    def test_one_bad_file_does_not_stop_the_others(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "a.sarif"), "w", encoding="utf-8") as handle:
                handle.write("not json")
            doc = base_doc()
            doc["version"] = "2.1"
            with open(os.path.join(tmp, "b.sarif"), "w", encoding="utf-8") as handle:
                json.dump(doc, handle)
            result = scan_path(tmp, options())
            self.assertEqual(result.files_scanned, 2)
            self.assertTrue(result.errors)
            self.assertIn("SRF-001", codes(result))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
