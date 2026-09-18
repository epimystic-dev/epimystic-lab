"""Per-rule behaviour.

Every rule gets three things at minimum:

  1. a positive case - a mutation of the known-clean base document that
     makes exactly that rule fire,
  2. a false-positive guard - the shape that looks similar but is legal,
     asserted NOT to fire,
  3. a --disable case - the same positive input with the rule turned off.

Assertions are on input -> rule code / severity / message substance. No test
here asserts an internal call shape.
"""

from __future__ import annotations

import unittest

from sarifcheck.rules import ALL_RULES, RULES_BY_ID, resolve_rule_reference
from sarifcheck.parse import build_index
from sarifcheck.types import Profile, Severity

from tests.support import (
    base_doc,
    base_location,
    base_result,
    base_rule,
    base_run,
    codes,
    messages_for,
    props_for,
    scan_doc,
)


def severity_of(result, rule_id):
    return set(f.severity for f in result.findings if f.rule_id == rule_id)


class BaselineTests(unittest.TestCase):
    def test_base_document_is_clean(self):
        # Every other test in this file is a mutation of this document, so a
        # finding elsewhere is attributable to the mutation.
        self.assertEqual(codes(scan_doc(base_doc())), set())

    def test_base_document_scans_one_file(self):
        self.assertEqual(scan_doc(base_doc()).files_scanned, 1)


class RuleRegistryTests(unittest.TestCase):
    def test_ids_are_unique(self):
        ids = [rule.id for rule in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_are_contiguous_srf_codes(self):
        expected = ["SRF-" + str(n).zfill(3) for n in range(1, len(ALL_RULES) + 1)]
        self.assertEqual([rule.id for rule in ALL_RULES], expected)

    def test_every_rule_has_a_title_and_description(self):
        for rule in ALL_RULES:
            self.assertTrue(rule.title.strip(), rule.id)
            self.assertGreater(len(rule.description.strip()), 40, rule.id)

    def test_every_rule_has_a_known_severity(self):
        for rule in ALL_RULES:
            self.assertIn(rule.severity, (Severity.HIGH, Severity.MEDIUM, Severity.INFO))

    def test_every_rule_has_a_known_profile(self):
        for rule in ALL_RULES:
            self.assertIn(rule.profile, (Profile.SPEC, Profile.INGEST, Profile.HYGIENE))

    def test_rules_by_id_covers_the_table(self):
        self.assertEqual(len(RULES_BY_ID), len(ALL_RULES))

    def test_at_least_eight_distinct_rules(self):
        self.assertGreaterEqual(len(ALL_RULES), 8)

    def test_no_rule_description_contains_a_non_ascii_character(self):
        for rule in ALL_RULES:
            blob = rule.id + rule.title + rule.description
            self.assertTrue(all(ord(c) < 128 for c in blob), rule.id)


class RuleReferenceResolutionTests(unittest.TestCase):
    def index_for(self, doc):
        return build_index(doc).runs[0]

    def test_top_level_rule_id_resolves(self):
        doc = base_doc()
        ref = resolve_rule_reference(base_result(doc), self.index_for(doc))
        self.assertTrue(ref.has_reference)
        self.assertEqual(ref.rule_id, "FX001")

    def test_rule_object_index_only_counts_as_a_reference(self):
        doc = base_doc()
        result = base_result(doc)
        del result["ruleId"]
        del result["ruleIndex"]
        result["rule"] = {"index": 0}
        ref = resolve_rule_reference(result, self.index_for(doc))
        self.assertTrue(ref.has_reference)
        self.assertEqual(ref.index_source, "rule.index")

    def test_rule_object_id_only_counts_as_a_reference(self):
        doc = base_doc()
        result = base_result(doc)
        del result["ruleId"]
        del result["ruleIndex"]
        result["rule"] = {"id": "FX001"}
        ref = resolve_rule_reference(result, self.index_for(doc))
        self.assertTrue(ref.has_reference)
        self.assertEqual(ref.id_source, "rule.id")

    def test_rule_index_minus_one_is_not_a_reference(self):
        doc = base_doc()
        result = base_result(doc)
        del result["ruleId"]
        result["ruleIndex"] = -1
        ref = resolve_rule_reference(result, self.index_for(doc))
        self.assertFalse(ref.has_reference)

    def test_tool_component_reference_is_flagged(self):
        doc = base_doc()
        result = base_result(doc)
        result["rule"] = {"index": 3, "toolComponent": {"index": 0}}
        ref = resolve_rule_reference(result, self.index_for(doc))
        self.assertTrue(ref.via_tool_component)

    def test_bool_is_not_accepted_as_a_rule_index(self):
        doc = base_doc()
        result = base_result(doc)
        del result["ruleId"]
        result["ruleIndex"] = True
        ref = resolve_rule_reference(result, self.index_for(doc))
        self.assertIsNone(ref.rule_index)


class Srf001VersionTests(unittest.TestCase):
    def test_wrong_version_fires(self):
        doc = base_doc()
        doc["version"] = "2.1"
        self.assertIn("SRF-001", codes(scan_doc(doc)))

    def test_absent_version_fires(self):
        doc = base_doc()
        del doc["version"]
        self.assertIn("SRF-001", codes(scan_doc(doc)))

    def test_non_string_version_fires(self):
        doc = base_doc()
        doc["version"] = 2.1
        self.assertIn("SRF-001", codes(scan_doc(doc)))

    def test_correct_version_does_not_fire(self):
        self.assertNotIn("SRF-001", codes(scan_doc(base_doc())))

    def test_recognised_old_version_is_owned_by_srf002(self):
        doc = base_doc()
        doc["version"] = "2.0.0"
        found = codes(scan_doc(doc))
        self.assertNotIn("SRF-001", found)
        self.assertIn("SRF-002", found)

    def test_disable(self):
        doc = base_doc()
        doc["version"] = "2.1"
        self.assertNotIn("SRF-001", codes(scan_doc(doc, disabled=["SRF-001"])))

    def test_severity_is_high(self):
        doc = base_doc()
        doc["version"] = "2.1"
        self.assertEqual(severity_of(scan_doc(doc), "SRF-001"), {Severity.HIGH})


class Srf002OldVersionTests(unittest.TestCase):
    def test_two_zero_zero_fires(self):
        doc = base_doc()
        doc["version"] = "2.0.0"
        self.assertIn("SRF-002", codes(scan_doc(doc)))

    def test_prerelease_fires(self):
        doc = base_doc()
        doc["version"] = "2.1.0-CSD.1"
        self.assertIn("SRF-002", codes(scan_doc(doc)))

    def test_current_version_does_not_fire(self):
        self.assertNotIn("SRF-002", codes(scan_doc(base_doc())))

    def test_unrecognised_junk_version_does_not_fire(self):
        doc = base_doc()
        doc["version"] = "banana"
        self.assertNotIn("SRF-002", codes(scan_doc(doc)))

    def test_message_names_the_version(self):
        doc = base_doc()
        doc["version"] = "2.0.0"
        self.assertIn("2.0.0", messages_for(scan_doc(doc), "SRF-002")[0])

    def test_disable(self):
        doc = base_doc()
        doc["version"] = "2.0.0"
        self.assertNotIn("SRF-002", codes(scan_doc(doc, disabled=["SRF-002"])))


class Srf003SchemaTests(unittest.TestCase):
    def test_absent_schema_fires_medium(self):
        doc = base_doc()
        del doc["$schema"]
        result = scan_doc(doc)
        self.assertIn("SRF-003", codes(result))
        self.assertEqual(severity_of(result, "SRF-003"), {Severity.MEDIUM})

    def test_schemastore_url_is_accepted(self):
        self.assertNotIn("SRF-003", codes(scan_doc(base_doc())))

    def test_oasis_style_url_is_accepted(self):
        doc = base_doc()
        doc["$schema"] = (
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
            "sarif-schema-2.1.0.json"
        )
        self.assertNotIn("SRF-003", codes(scan_doc(doc)))

    def test_rtm_variant_is_accepted(self):
        doc = base_doc()
        doc["$schema"] = "https://example.invalid/sarif-schema-2.1.0-rtm.5.json"
        self.assertNotIn("SRF-003", codes(scan_doc(doc)))

    def test_bare_sarif_2_1_0_filename_is_accepted(self):
        doc = base_doc()
        doc["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json"
        self.assertNotIn("SRF-003", codes(scan_doc(doc)))

    def test_fragment_and_query_are_ignored(self):
        doc = base_doc()
        doc["$schema"] = "https://example.invalid/sarif-schema-2.1.0.json?v=1#top"
        self.assertNotIn("SRF-003", codes(scan_doc(doc)))

    def test_other_sarif_version_is_high(self):
        doc = base_doc()
        doc["$schema"] = "https://example.invalid/sarif-schema-2.0.0.json"
        result = scan_doc(doc)
        self.assertEqual(severity_of(result, "SRF-003"), {Severity.HIGH})

    def test_unrecognised_sarif_url_is_info(self):
        doc = base_doc()
        doc["$schema"] = "https://example.invalid/mirror/sarif/latest.json"
        result = scan_doc(doc)
        self.assertEqual(severity_of(result, "SRF-003"), {Severity.INFO})

    def test_disable(self):
        doc = base_doc()
        del doc["$schema"]
        self.assertNotIn("SRF-003", codes(scan_doc(doc, disabled=["SRF-003"])))


class Srf004AbsoluteUriTests(unittest.TestCase):
    def set_uri(self, doc, uri, keep_base=False):
        artifact = base_location(doc)["artifactLocation"]
        artifact["uri"] = uri
        if not keep_base:
            artifact.pop("uriBaseId", None)
        return doc

    def test_file_uri_fires(self):
        doc = self.set_uri(base_doc(), "file:///build/workspace/src/a.py")
        self.assertIn("SRF-004", codes(scan_doc(doc)))

    def test_posix_absolute_fires(self):
        doc = self.set_uri(base_doc(), "/build/workspace/src/a.py")
        self.assertIn("SRF-004", codes(scan_doc(doc)))

    def test_windows_drive_fires(self):
        doc = self.set_uri(base_doc(), "C:/build/src/a.py")
        self.assertIn("SRF-004", codes(scan_doc(doc)))

    def test_unc_fires(self):
        doc = self.set_uri(base_doc(), "\\\\buildhost\\share\\a.py")
        self.assertIn("SRF-004", codes(scan_doc(doc)))

    def test_relative_uri_with_base_id_does_not_fire(self):
        self.assertNotIn("SRF-004", codes(scan_doc(base_doc())))

    def test_relative_uri_without_base_id_does_not_fire(self):
        doc = self.set_uri(base_doc(), "src/a.py")
        self.assertNotIn("SRF-004", codes(scan_doc(doc)))

    def test_https_uri_does_not_fire(self):
        doc = self.set_uri(base_doc(), "https://example.invalid/a.py")
        self.assertNotIn("SRF-004", codes(scan_doc(doc)))

    def test_absolute_working_directory_does_not_fire(self):
        doc = base_doc()
        base_run(doc)["invocations"] = [
            {"workingDirectory": {"uri": "file:///build/workspace/"}}
        ]
        self.assertNotIn("SRF-004", codes(scan_doc(doc)))

    def test_absolute_original_uri_base_id_does_not_fire(self):
        # The base document already carries an absolute originalUriBaseIds
        # entry, which is required to be absolute.
        self.assertNotIn("SRF-004", codes(scan_doc(base_doc())))

    def test_absolute_artifacts_entry_does_not_fire(self):
        doc = base_doc()
        base_run(doc)["artifacts"] = [
            {"location": {"uri": "file:///build/workspace/src/a.py"}}
        ]
        self.assertNotIn("SRF-004", codes(scan_doc(doc)))

    def test_message_names_the_spec_clause_when_base_id_present(self):
        doc = self.set_uri(base_doc(), "/build/a.py", keep_base=True)
        self.assertIn("3.4.4", messages_for(scan_doc(doc), "SRF-004")[0])

    def test_message_does_not_reprint_the_path(self):
        doc = self.set_uri(base_doc(), "/build/secretish/a.py")
        self.assertNotIn("secretish", messages_for(scan_doc(doc), "SRF-004")[0])

    def test_thread_flow_location_is_visited(self):
        doc = base_doc()
        base_result(doc)["codeFlows"] = [
            {"threadFlows": [{"locations": [{"location": {"physicalLocation": {
                "artifactLocation": {"uri": "/build/a.py"}}}}]}]}
        ]
        self.assertIn("SRF-004", codes(scan_doc(doc)))

    def test_fix_artifact_location_is_visited(self):
        doc = base_doc()
        base_result(doc)["fixes"] = [
            {"artifactChanges": [
                {"artifactLocation": {"uri": "/build/a.py"},
                 "replacements": [{"deletedRegion": {"startLine": 1}}]}
            ]}
        ]
        self.assertIn("SRF-004", codes(scan_doc(doc)))

    def test_disable(self):
        doc = self.set_uri(base_doc(), "/build/a.py")
        self.assertNotIn("SRF-004", codes(scan_doc(doc, disabled=["SRF-004"])))


class Srf005UriReferenceTests(unittest.TestCase):
    def set_uri(self, doc, uri):
        base_location(doc)["artifactLocation"]["uri"] = uri
        return doc

    def test_backslash_fires(self):
        self.assertIn("SRF-005", codes(scan_doc(self.set_uri(base_doc(), "src\\a.py"))))

    def test_raw_space_fires(self):
        self.assertIn("SRF-005", codes(scan_doc(self.set_uri(base_doc(), "src/a b.py"))))

    def test_percent_encoded_space_does_not_fire(self):
        self.assertNotIn(
            "SRF-005", codes(scan_doc(self.set_uri(base_doc(), "src/a%20b.py")))
        )

    def test_clean_relative_uri_does_not_fire(self):
        self.assertNotIn("SRF-005", codes(scan_doc(base_doc())))

    def test_message_names_the_defect(self):
        result = scan_doc(self.set_uri(base_doc(), "src\\a.py"))
        self.assertIn("backslash-separator", messages_for(result, "SRF-005")[0])

    def test_disable(self):
        doc = self.set_uri(base_doc(), "src\\a.py")
        self.assertNotIn("SRF-005", codes(scan_doc(doc, disabled=["SRF-005"])))


class Srf006PathInMessageTests(unittest.TestCase):
    def set_message(self, doc, text):
        base_result(doc)["message"] = {"text": text}
        return doc

    def test_home_path_in_message_fires(self):
        doc = self.set_message(base_doc(), "sink reached in /home/devuser/a.py")
        self.assertIn("SRF-006", codes(scan_doc(doc)))

    def test_windows_path_in_message_fires(self):
        doc = self.set_message(base_doc(), "sink in C:\\Users\\devuser\\a.py")
        self.assertIn("SRF-006", codes(scan_doc(doc)))

    def test_relative_path_in_message_does_not_fire(self):
        doc = self.set_message(base_doc(), "sink reached in src/widget/a.py")
        self.assertNotIn("SRF-006", codes(scan_doc(doc)))

    def test_plain_prose_does_not_fire(self):
        self.assertNotIn("SRF-006", codes(scan_doc(base_doc())))

    def test_message_reports_shape_count_and_offset_not_the_path(self):
        doc = self.set_message(base_doc(), "x /home/devuser/a.py")
        message = messages_for(scan_doc(doc), "SRF-006")[0]
        self.assertIn("posix-home", message)
        self.assertIn("occurrence", message)
        self.assertNotIn("devuser", message)

    def test_ignore_rule_id_suppresses_for_that_rule_only(self):
        doc = self.set_message(base_doc(), "sink in /home/devuser/a.py")
        self.assertNotIn(
            "SRF-006", codes(scan_doc(doc, ignore_rule_ids=["FX001"]))
        )

    def test_ignore_rule_id_for_a_different_rule_does_not_suppress(self):
        doc = self.set_message(base_doc(), "sink in /home/devuser/a.py")
        self.assertIn("SRF-006", codes(scan_doc(doc, ignore_rule_ids=["OTHER"])))

    def test_allow_path_in_message_suppresses_everything(self):
        doc = self.set_message(base_doc(), "sink in /home/devuser/a.py")
        self.assertNotIn("SRF-006", codes(scan_doc(doc, allow_path_in_message=True)))

    def test_severity_is_medium(self):
        doc = self.set_message(base_doc(), "sink in /home/devuser/a.py")
        self.assertEqual(severity_of(scan_doc(doc), "SRF-006"), {Severity.MEDIUM})

    def test_snippet_holds_the_match_for_show_matches(self):
        doc = self.set_message(base_doc(), "sink in /home/devuser/a.py")
        finding = [f for f in scan_doc(doc).findings if f.rule_id == "SRF-006"][0]
        self.assertIn("/home/devuser", finding.snippet)

    def test_disable(self):
        doc = self.set_message(base_doc(), "sink in /home/devuser/a.py")
        self.assertNotIn("SRF-006", codes(scan_doc(doc, disabled=["SRF-006"])))


class Srf007HomeInBuildUriTests(unittest.TestCase):
    def test_home_in_original_uri_base_id_fires(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"]["SRCROOT"]["uri"] = "file:///home/devuser/ws/"
        self.assertIn("SRF-007", codes(scan_doc(doc)))

    def test_home_in_working_directory_fires(self):
        doc = base_doc()
        base_run(doc)["invocations"] = [
            {"workingDirectory": {"uri": "/Users/devuser/ws/"}}
        ]
        self.assertIn("SRF-007", codes(scan_doc(doc)))

    def test_home_in_artifacts_location_fires(self):
        doc = base_doc()
        base_run(doc)["artifacts"] = [
            {"location": {"uri": "C:\\Users\\devuser\\ws\\a.py"}}
        ]
        self.assertIn("SRF-007", codes(scan_doc(doc)))

    def test_build_root_without_home_does_not_fire(self):
        self.assertNotIn("SRF-007", codes(scan_doc(base_doc())))

    def test_relative_uri_does_not_fire(self):
        doc = base_doc()
        base_run(doc)["artifacts"] = [{"location": {"uri": "src/home/devuser/a.py"}}]
        self.assertNotIn("SRF-007", codes(scan_doc(doc)))

    def test_message_redacts_the_account_segment(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"]["SRCROOT"]["uri"] = "file:///home/devuser/ws/"
        message = messages_for(scan_doc(doc), "SRF-007")[0]
        self.assertNotIn("devuser", message)
        self.assertIn("redacted", message)

    def test_message_refuses_the_leak_framing(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"]["SRCROOT"]["uri"] = "file:///home/devuser/ws/"
        message = messages_for(scan_doc(doc), "SRF-007")[0].lower()
        self.assertNotIn("leak", message)
        self.assertIn("not proof", message)

    def test_disable(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"]["SRCROOT"]["uri"] = "file:///home/devuser/ws/"
        self.assertNotIn("SRF-007", codes(scan_doc(doc, disabled=["SRF-007"])))


class Srf008NoRuleReferenceTests(unittest.TestCase):
    def strip(self, doc):
        result = base_result(doc)
        result.pop("ruleId", None)
        result.pop("ruleIndex", None)
        result.pop("rule", None)
        return doc

    def test_no_reference_fires(self):
        self.assertIn("SRF-008", codes(scan_doc(self.strip(base_doc()))))

    def test_rule_id_only_does_not_fire(self):
        doc = self.strip(base_doc())
        base_result(doc)["ruleId"] = "FX001"
        self.assertNotIn("SRF-008", codes(scan_doc(doc)))

    def test_rule_index_only_does_not_fire(self):
        doc = self.strip(base_doc())
        base_result(doc)["ruleIndex"] = 0
        self.assertNotIn("SRF-008", codes(scan_doc(doc)))

    def test_rule_object_index_only_does_not_fire(self):
        doc = self.strip(base_doc())
        base_result(doc)["rule"] = {"index": 0}
        self.assertNotIn("SRF-008", codes(scan_doc(doc)))

    def test_rule_index_minus_one_still_fires(self):
        doc = self.strip(base_doc())
        base_result(doc)["ruleIndex"] = -1
        self.assertIn("SRF-008", codes(scan_doc(doc)))

    def test_severity_is_medium_not_high(self):
        self.assertEqual(
            severity_of(scan_doc(self.strip(base_doc())), "SRF-008"), {Severity.MEDIUM}
        )

    def test_message_does_not_call_it_invalid(self):
        message = messages_for(scan_doc(self.strip(base_doc())), "SRF-008")[0]
        self.assertIn("legal SARIF", message)

    def test_disable(self):
        doc = self.strip(base_doc())
        self.assertNotIn("SRF-008", codes(scan_doc(doc, disabled=["SRF-008"])))


class Srf009DanglingRuleIdTests(unittest.TestCase):
    def test_unknown_rule_id_fires_when_metadata_exists(self):
        doc = base_doc()
        base_result(doc)["ruleId"] = "FX999"
        base_result(doc).pop("ruleIndex", None)
        self.assertIn("SRF-009", codes(scan_doc(doc)))

    def test_known_rule_id_does_not_fire(self):
        self.assertNotIn("SRF-009", codes(scan_doc(base_doc())))

    def test_absent_rules_array_suppresses_the_rule(self):
        doc = base_doc()
        del doc["runs"][0]["tool"]["driver"]["rules"]
        base_result(doc).pop("ruleIndex", None)
        base_result(doc)["ruleId"] = "FX999"
        self.assertNotIn("SRF-009", codes(scan_doc(doc)))

    def test_empty_rules_array_suppresses_the_rule(self):
        doc = base_doc()
        doc["runs"][0]["tool"]["driver"]["rules"] = []
        base_result(doc).pop("ruleIndex", None)
        base_result(doc)["ruleId"] = "FX999"
        self.assertNotIn("SRF-009", codes(scan_doc(doc)))

    def test_extension_rule_id_resolves(self):
        doc = base_doc()
        doc["runs"][0]["tool"]["extensions"] = [
            {"name": "ext", "rules": [{"id": "EXT1"}]}
        ]
        base_result(doc)["ruleId"] = "EXT1"
        base_result(doc).pop("ruleIndex", None)
        self.assertNotIn("SRF-009", codes(scan_doc(doc)))

    def test_severity_is_medium(self):
        doc = base_doc()
        base_result(doc)["ruleId"] = "FX999"
        base_result(doc).pop("ruleIndex", None)
        self.assertEqual(severity_of(scan_doc(doc), "SRF-009"), {Severity.MEDIUM})

    def test_disable(self):
        doc = base_doc()
        base_result(doc)["ruleId"] = "FX999"
        base_result(doc).pop("ruleIndex", None)
        self.assertNotIn("SRF-009", codes(scan_doc(doc, disabled=["SRF-009"])))


class Srf010NoRuleMetadataTests(unittest.TestCase):
    def strip_rules(self, doc):
        del doc["runs"][0]["tool"]["driver"]["rules"]
        base_result(doc).pop("ruleIndex", None)
        return doc

    def test_absent_rules_array_fires_once(self):
        result = scan_doc(self.strip_rules(base_doc()))
        self.assertEqual(len(messages_for(result, "SRF-010")), 1)

    def test_present_rules_array_does_not_fire(self):
        self.assertNotIn("SRF-010", codes(scan_doc(base_doc())))

    def test_run_with_no_results_does_not_fire(self):
        doc = self.strip_rules(base_doc())
        base_run(doc)["results"] = []
        self.assertNotIn("SRF-010", codes(scan_doc(doc)))

    def test_severity_is_info(self):
        self.assertEqual(
            severity_of(scan_doc(self.strip_rules(base_doc())), "SRF-010"),
            {Severity.INFO},
        )

    def test_disable(self):
        doc = self.strip_rules(base_doc())
        self.assertNotIn("SRF-010", codes(scan_doc(doc, disabled=["SRF-010"])))


class Srf011RuleIndexTests(unittest.TestCase):
    def test_out_of_bounds_fires(self):
        doc = base_doc()
        base_result(doc)["ruleIndex"] = 5
        self.assertIn("SRF-011", codes(scan_doc(doc)))

    def test_huge_unsigned_index_fires(self):
        doc = base_doc()
        base_result(doc)["ruleIndex"] = 18446744073709551615
        self.assertIn("SRF-011", codes(scan_doc(doc)))

    def test_minus_one_does_not_fire(self):
        doc = base_doc()
        base_result(doc)["ruleIndex"] = -1
        self.assertNotIn("SRF-011", codes(scan_doc(doc)))

    def test_absent_index_does_not_fire(self):
        doc = base_doc()
        del base_result(doc)["ruleIndex"]
        self.assertNotIn("SRF-011", codes(scan_doc(doc)))

    def test_below_minus_one_fires(self):
        doc = base_doc()
        base_result(doc)["ruleIndex"] = -7
        self.assertIn("SRF-011", codes(scan_doc(doc)))

    def test_disagreement_with_rule_id_fires(self):
        doc = base_doc()
        doc["runs"][0]["tool"]["driver"]["rules"].append({"id": "FX002"})
        base_result(doc)["ruleIndex"] = 1
        self.assertIn("SRF-011", codes(scan_doc(doc)))

    def test_agreement_does_not_fire(self):
        doc = base_doc()
        doc["runs"][0]["tool"]["driver"]["rules"].append({"id": "FX002"})
        base_result(doc)["ruleId"] = "FX002"
        base_result(doc)["ruleIndex"] = 1
        self.assertNotIn("SRF-011", codes(scan_doc(doc)))

    def test_index_with_no_rules_array_does_not_fire(self):
        doc = base_doc()
        doc["runs"][0]["tool"]["driver"]["rules"] = []
        base_result(doc)["ruleIndex"] = 3
        self.assertNotIn("SRF-011", codes(scan_doc(doc)))

    def test_tool_component_qualified_index_is_skipped(self):
        doc = base_doc()
        result = base_result(doc)
        del result["ruleIndex"]
        result["rule"] = {"index": 99, "toolComponent": {"index": 0}}
        self.assertNotIn("SRF-011", codes(scan_doc(doc)))

    def test_disable(self):
        doc = base_doc()
        base_result(doc)["ruleIndex"] = 5
        self.assertNotIn("SRF-011", codes(scan_doc(doc, disabled=["SRF-011"])))


class Srf012MessageTests(unittest.TestCase):
    def test_no_text_and_no_id_fires(self):
        doc = base_doc()
        base_result(doc)["message"] = {}
        self.assertIn("SRF-012", codes(scan_doc(doc)))

    def test_absent_message_object_fires(self):
        doc = base_doc()
        del base_result(doc)["message"]
        self.assertIn("SRF-012", codes(scan_doc(doc)))

    def test_empty_text_fires(self):
        doc = base_doc()
        base_result(doc)["message"] = {"text": "   "}
        self.assertIn("SRF-012", codes(scan_doc(doc)))

    def test_resolvable_message_id_does_not_fire(self):
        doc = base_doc()
        base_result(doc)["message"] = {"id": "default", "arguments": ["x"]}
        self.assertNotIn("SRF-012", codes(scan_doc(doc)))

    def test_dangling_message_id_fires(self):
        doc = base_doc()
        base_result(doc)["message"] = {"id": "nope"}
        self.assertIn("SRF-012", codes(scan_doc(doc)))

    def test_message_id_with_unresolvable_descriptor_does_not_fire(self):
        doc = base_doc()
        del doc["runs"][0]["tool"]["driver"]["rules"]
        base_result(doc).pop("ruleIndex", None)
        base_result(doc)["message"] = {"id": "nope"}
        self.assertNotIn("SRF-012", codes(scan_doc(doc)))

    def test_plain_text_does_not_fire(self):
        self.assertNotIn("SRF-012", codes(scan_doc(base_doc())))

    def test_disable(self):
        doc = base_doc()
        base_result(doc)["message"] = {}
        self.assertNotIn("SRF-012", codes(scan_doc(doc, disabled=["SRF-012"])))


class Srf013LocationsTests(unittest.TestCase):
    def test_empty_locations_fires_medium(self):
        doc = base_doc()
        base_result(doc)["locations"] = []
        result = scan_doc(doc)
        self.assertIn("SRF-013", codes(result))
        self.assertEqual(severity_of(result, "SRF-013"), {Severity.MEDIUM})

    def test_absent_locations_fires(self):
        doc = base_doc()
        del base_result(doc)["locations"]
        self.assertIn("SRF-013", codes(scan_doc(doc)))

    def test_non_fail_kind_downgrades_to_info(self):
        doc = base_doc()
        base_result(doc)["locations"] = []
        base_result(doc)["kind"] = "notApplicable"
        base_result(doc)["level"] = "none"
        result = scan_doc(doc)
        self.assertEqual(severity_of(result, "SRF-013"), {Severity.INFO})

    def test_populated_locations_does_not_fire(self):
        self.assertNotIn("SRF-013", codes(scan_doc(base_doc())))

    def test_message_names_which_authority_it_cites(self):
        doc = base_doc()
        base_result(doc)["locations"] = []
        message = messages_for(scan_doc(doc), "SRF-013")[0]
        self.assertIn("spec permits", message)
        self.assertIn("documented ingest", message)

    def test_disable(self):
        doc = base_doc()
        base_result(doc)["locations"] = []
        self.assertNotIn("SRF-013", codes(scan_doc(doc, disabled=["SRF-013"])))


class Srf014RegionTests(unittest.TestCase):
    def set_region(self, doc, region):
        base_location(doc)["region"] = region
        return doc

    def test_start_line_zero_fires(self):
        self.assertIn("SRF-014", codes(scan_doc(self.set_region(base_doc(), {"startLine": 0}))))

    def test_negative_start_column_fires(self):
        doc = self.set_region(base_doc(), {"startLine": 1, "startColumn": -3})
        self.assertIn("SRF-014", codes(scan_doc(doc)))

    def test_end_line_zero_fires(self):
        doc = self.set_region(base_doc(), {"startLine": 1, "endLine": 0})
        self.assertIn("SRF-014", codes(scan_doc(doc)))

    def test_line_one_does_not_fire(self):
        self.assertNotIn("SRF-014", codes(scan_doc(base_doc())))

    def test_binary_region_without_start_line_does_not_fire(self):
        doc = self.set_region(base_doc(), {"byteOffset": 0, "byteLength": 16})
        self.assertNotIn("SRF-014", codes(scan_doc(doc)))

    def test_char_offset_zero_is_not_flagged(self):
        doc = self.set_region(base_doc(), {"charOffset": 0, "charLength": 4})
        self.assertNotIn("SRF-014", codes(scan_doc(doc)))

    def test_context_region_is_checked(self):
        doc = base_doc()
        base_location(doc)["contextRegion"] = {"startLine": 0}
        self.assertIn("SRF-014", codes(scan_doc(doc)))

    def test_non_integer_region_value_is_ignored(self):
        doc = self.set_region(base_doc(), {"startLine": "1"})
        self.assertNotIn("SRF-014", codes(scan_doc(doc)))

    def test_disable(self):
        doc = self.set_region(base_doc(), {"startLine": 0})
        self.assertNotIn("SRF-014", codes(scan_doc(doc, disabled=["SRF-014"])))


class Srf015KindLevelTests(unittest.TestCase):
    def test_pass_with_error_level_fires(self):
        doc = base_doc()
        base_result(doc)["kind"] = "pass"
        base_result(doc)["level"] = "error"
        self.assertIn("SRF-015", codes(scan_doc(doc)))

    def test_fail_with_error_level_does_not_fire(self):
        self.assertNotIn("SRF-015", codes(scan_doc(base_doc())))

    def test_pass_with_level_none_does_not_fire(self):
        doc = base_doc()
        base_result(doc)["kind"] = "pass"
        base_result(doc)["level"] = "none"
        self.assertNotIn("SRF-015", codes(scan_doc(doc)))

    def test_pass_with_absent_level_does_not_fire(self):
        doc = base_doc()
        base_result(doc)["kind"] = "pass"
        del base_result(doc)["level"]
        self.assertNotIn("SRF-015", codes(scan_doc(doc)))

    def test_absent_kind_does_not_fire(self):
        doc = base_doc()
        del base_result(doc)["kind"]
        self.assertNotIn("SRF-015", codes(scan_doc(doc)))

    def test_severity_is_high(self):
        doc = base_doc()
        base_result(doc)["kind"] = "open"
        self.assertEqual(severity_of(scan_doc(doc), "SRF-015"), {Severity.HIGH})

    def test_disable(self):
        doc = base_doc()
        base_result(doc)["kind"] = "pass"
        self.assertNotIn("SRF-015", codes(scan_doc(doc, disabled=["SRF-015"])))


class Srf016HardLimitTests(unittest.TestCase):
    def test_too_many_runs_fires(self):
        doc = base_doc()
        doc["runs"] = [base_run(doc)] * 3
        result = scan_doc(doc, limits={"max_runs_per_file": 2})
        self.assertIn("SRF-016", codes(result))

    def test_too_many_results_fires(self):
        doc = base_doc()
        base_run(doc)["results"] = [base_result(doc), base_result(doc)]
        self.assertIn("SRF-016", codes(scan_doc(doc, limits={"max_results_per_run": 1})))

    def test_too_many_rules_fires(self):
        doc = base_doc()
        self.assertIn("SRF-016", codes(scan_doc(doc, limits={"max_rules_per_run": 0})))

    def test_too_many_locations_fires(self):
        doc = base_doc()
        loc = base_result(doc)["locations"][0]
        base_result(doc)["locations"] = [loc, loc, loc]
        self.assertIn(
            "SRF-016", codes(scan_doc(doc, limits={"max_locations_per_result": 2}))
        )

    def test_thread_flow_total_is_summed_across_code_flows(self):
        doc = base_doc()
        flow = {"threadFlows": [{"locations": [{"location": {}}, {"location": {}}]}]}
        base_result(doc)["codeFlows"] = [flow, flow]
        # 4 in total, 2 per codeFlow: a per-codeFlow count would miss this.
        self.assertIn(
            "SRF-016",
            codes(scan_doc(doc, limits={"max_threadflow_locations_per_result": 3})),
        )

    def test_too_many_tags_fires(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 21}
        self.assertIn("SRF-016", codes(scan_doc(doc)))

    def test_extension_rules_count_toward_the_per_run_rule_limit(self):
        doc = base_doc()
        doc["runs"][0]["tool"]["extensions"] = [
            {"name": "ext", "rules": [{"id": "E1"}, {"id": "E2"}]}
        ]
        self.assertIn("SRF-016", codes(scan_doc(doc, limits={"max_rules_per_run": 2})))

    def test_under_the_ceiling_does_not_fire(self):
        self.assertNotIn("SRF-016", codes(scan_doc(base_doc())))

    def test_message_carries_the_source_url_and_date(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 21}
        message = messages_for(scan_doc(doc), "SRF-016")[0]
        self.assertIn("https://docs.github.com/", message)
        self.assertIn("2026-09-18", message)

    def test_override_raises_the_ceiling(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 21}
        self.assertNotIn(
            "SRF-016", codes(scan_doc(doc, limits={"max_tags_per_rule": 100}))
        )

    def test_disable(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 21}
        self.assertNotIn("SRF-016", codes(scan_doc(doc, disabled=["SRF-016"])))


class Srf017SoftLimitTests(unittest.TestCase):
    def test_eleven_tags_fires_soft_only(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 11}
        found = codes(scan_doc(doc))
        self.assertIn("SRF-017", found)
        self.assertNotIn("SRF-016", found)

    def test_twenty_one_tags_fires_hard_not_soft(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 21}
        found = codes(scan_doc(doc))
        self.assertIn("SRF-016", found)
        self.assertNotIn("SRF-017", found)

    def test_ten_tags_does_not_fire(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 10}
        self.assertNotIn("SRF-017", codes(scan_doc(doc)))

    def test_soft_results_ceiling(self):
        doc = base_doc()
        base_run(doc)["results"] = [base_result(doc), base_result(doc)]
        self.assertIn(
            "SRF-017", codes(scan_doc(doc, limits={"soft_results_per_run": 1}))
        )

    def test_severity_is_medium(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 11}
        self.assertEqual(severity_of(scan_doc(doc), "SRF-017"), {Severity.MEDIUM})

    def test_disable(self):
        doc = base_doc()
        base_rule(doc)["properties"] = {"tags": ["t"] * 11}
        self.assertNotIn("SRF-017", codes(scan_doc(doc, disabled=["SRF-017"])))


class Srf018FingerprintTests(unittest.TestCase):
    def test_missing_fingerprints_fires(self):
        doc = base_doc()
        del base_result(doc)["partialFingerprints"]
        self.assertIn("SRF-018", codes(scan_doc(doc)))

    def test_empty_fingerprints_fires(self):
        doc = base_doc()
        base_result(doc)["partialFingerprints"] = {}
        self.assertIn("SRF-018", codes(scan_doc(doc)))

    def test_present_fingerprints_does_not_fire(self):
        self.assertNotIn("SRF-018", codes(scan_doc(base_doc())))

    def test_one_finding_per_run_not_per_result(self):
        doc = base_doc()
        result = base_result(doc)
        del result["partialFingerprints"]
        base_run(doc)["results"] = [result, dict(result), dict(result)]
        self.assertEqual(len(messages_for(scan_doc(doc), "SRF-018")), 1)

    def test_message_counts_the_affected_results(self):
        doc = base_doc()
        del base_result(doc)["partialFingerprints"]
        self.assertIn("1 of 1 results", messages_for(scan_doc(doc), "SRF-018")[0])

    def test_message_does_not_claim_churn(self):
        doc = base_doc()
        del base_result(doc)["partialFingerprints"]
        message = messages_for(scan_doc(doc), "SRF-018")[0]
        self.assertNotIn("churn", message)

    def test_disable(self):
        doc = base_doc()
        del base_result(doc)["partialFingerprints"]
        self.assertNotIn("SRF-018", codes(scan_doc(doc, disabled=["SRF-018"])))


class Srf019RuleDocsTests(unittest.TestCase):
    def test_missing_help_fires(self):
        doc = base_doc()
        del base_rule(doc)["help"]
        self.assertIn("SRF-019", codes(scan_doc(doc)))

    def test_missing_full_description_fires(self):
        doc = base_doc()
        del base_rule(doc)["fullDescription"]
        self.assertIn("SRF-019", codes(scan_doc(doc)))

    def test_missing_short_description_fires(self):
        doc = base_doc()
        del base_rule(doc)["shortDescription"]
        self.assertIn("SRF-019", codes(scan_doc(doc)))

    def test_all_three_present_does_not_fire(self):
        self.assertNotIn("SRF-019", codes(scan_doc(base_doc())))

    def test_empty_text_counts_as_missing(self):
        doc = base_doc()
        base_rule(doc)["help"] = {"text": ""}
        self.assertIn("SRF-019", codes(scan_doc(doc)))

    def test_message_lists_the_missing_fields(self):
        doc = base_doc()
        del base_rule(doc)["help"]
        del base_rule(doc)["fullDescription"]
        message = messages_for(scan_doc(doc), "SRF-019")[0]
        self.assertIn("fullDescription.text", message)
        self.assertIn("help.text", message)

    def test_disable(self):
        doc = base_doc()
        del base_rule(doc)["help"]
        self.assertNotIn("SRF-019", codes(scan_doc(doc, disabled=["SRF-019"])))


class Srf020UriBaseIdTests(unittest.TestCase):
    def test_undefined_base_id_fires(self):
        doc = base_doc()
        base_location(doc)["artifactLocation"]["uriBaseId"] = "REPOROOT"
        self.assertIn("SRF-020", codes(scan_doc(doc)))

    def test_defined_base_id_does_not_fire(self):
        self.assertNotIn("SRF-020", codes(scan_doc(base_doc())))

    def test_artifacts_base_id_is_checked(self):
        doc = base_doc()
        base_run(doc)["artifacts"] = [
            {"location": {"uri": "a.py", "uriBaseId": "NOWHERE"}}
        ]
        self.assertIn("SRF-020", codes(scan_doc(doc)))

    def test_external_property_files_suppress_the_rule(self):
        doc = base_doc()
        base_location(doc)["artifactLocation"]["uriBaseId"] = "REPOROOT"
        base_run(doc)["externalPropertyFileReferences"] = {"addresses": []}
        self.assertNotIn("SRF-020", codes(scan_doc(doc)))

    def test_one_finding_per_distinct_base_id(self):
        doc = base_doc()
        loc = base_result(doc)["locations"][0]
        base_result(doc)["locations"] = [loc, dict(loc)]
        base_location(doc)["artifactLocation"]["uriBaseId"] = "REPOROOT"
        self.assertLessEqual(len(messages_for(scan_doc(doc), "SRF-020")), 1)

    def test_disable(self):
        doc = base_doc()
        base_location(doc)["artifactLocation"]["uriBaseId"] = "REPOROOT"
        self.assertNotIn("SRF-020", codes(scan_doc(doc, disabled=["SRF-020"])))


class Srf021BaseChainTests(unittest.TestCase):
    def test_relative_root_fires(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {"SRCROOT": {"uri": "src/"}}
        self.assertIn("SRF-021", codes(scan_doc(doc)))

    def test_missing_root_uri_fires(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {"SRCROOT": {}}
        self.assertIn("SRF-021", codes(scan_doc(doc)))

    def test_dangling_parent_fires(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {
            "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"}
        }
        self.assertIn("SRF-021", codes(scan_doc(doc)))

    def test_cycle_fires(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {
            "A": {"uri": "a/", "uriBaseId": "B"},
            "B": {"uri": "b/", "uriBaseId": "A"},
        }
        self.assertIn("SRF-021", codes(scan_doc(doc)))

    def test_valid_two_step_chain_does_not_fire(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {
            "SRCROOT": {"uri": "src/", "uriBaseId": "REPOROOT"},
            "REPOROOT": {"uri": "file:///build/workspace/"},
        }
        self.assertNotIn("SRF-021", codes(scan_doc(doc)))

    def test_single_absolute_entry_does_not_fire(self):
        self.assertNotIn("SRF-021", codes(scan_doc(base_doc())))

    def test_cycle_message_names_the_cycle(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {
            "A": {"uri": "a/", "uriBaseId": "B"},
            "B": {"uri": "b/", "uriBaseId": "A"},
        }
        self.assertIn("cycle", messages_for(scan_doc(doc), "SRF-021")[0])

    def test_severity_is_high(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {"SRCROOT": {"uri": "src/"}}
        self.assertEqual(severity_of(scan_doc(doc), "SRF-021"), {Severity.HIGH})

    def test_disable(self):
        doc = base_doc()
        base_run(doc)["originalUriBaseIds"] = {"SRCROOT": {"uri": "src/"}}
        self.assertNotIn("SRF-021", codes(scan_doc(doc, disabled=["SRF-021"])))


class Srf022AutomationDetailsTests(unittest.TestCase):
    def two_runs(self, with_id):
        doc = base_doc()
        run = base_run(doc)
        if not with_id:
            run.pop("automationDetails", None)
        doc["runs"] = [run, dict(run)]
        return doc

    def test_multi_run_without_id_fires(self):
        self.assertIn("SRF-022", codes(scan_doc(self.two_runs(False))))

    def test_multi_run_with_id_does_not_fire(self):
        self.assertNotIn("SRF-022", codes(scan_doc(self.two_runs(True))))

    def test_single_run_without_id_does_not_fire(self):
        doc = base_doc()
        base_run(doc).pop("automationDetails", None)
        self.assertNotIn("SRF-022", codes(scan_doc(doc)))

    def test_empty_id_string_fires(self):
        doc = self.two_runs(True)
        doc["runs"][0]["automationDetails"] = {"id": ""}
        self.assertIn("SRF-022", codes(scan_doc(doc)))

    def test_disable(self):
        self.assertNotIn(
            "SRF-022", codes(scan_doc(self.two_runs(False), disabled=["SRF-022"]))
        )


class Srf023CompressedSizeTests(unittest.TestCase):
    def test_tiny_ceiling_fires(self):
        result = scan_doc(base_doc(), limits={"max_compressed_bytes": 1})
        self.assertIn("SRF-023", codes(result))

    def test_default_ceiling_does_not_fire_on_a_small_file(self):
        self.assertNotIn("SRF-023", codes(scan_doc(base_doc())))

    def test_message_reports_both_sizes(self):
        result = scan_doc(base_doc(), limits={"max_compressed_bytes": 1})
        message = messages_for(result, "SRF-023")[0]
        self.assertIn("gzip-compressed size", message)
        self.assertIn("raw", message)

    def test_compressed_size_is_smaller_than_raw_for_sarif(self):
        result = scan_doc(base_doc(), limits={"max_compressed_bytes": 1})
        message = messages_for(result, "SRF-023")[0]
        compressed = int(message.split("gzip-compressed size is ")[1].split(" ")[0])
        raw = int(message.split("(raw ")[1].split(" ")[0])
        self.assertLess(compressed, raw)

    def test_severity_is_high(self):
        result = scan_doc(base_doc(), limits={"max_compressed_bytes": 1})
        self.assertEqual(severity_of(result, "SRF-023"), {Severity.HIGH})

    def test_disable(self):
        result = scan_doc(
            base_doc(), limits={"max_compressed_bytes": 1}, disabled=["SRF-023"]
        )
        self.assertNotIn("SRF-023", codes(result))


class Srf024FragileShapeTests(unittest.TestCase):
    def test_empty_replacements_fires(self):
        doc = base_doc()
        base_result(doc)["fixes"] = [
            {"artifactChanges": [
                {"artifactLocation": {"uri": "a.py"}, "replacements": []}
            ]}
        ]
        self.assertIn("SRF-024", codes(scan_doc(doc)))

    def test_replacement_with_nothing_in_it_fires(self):
        doc = base_doc()
        base_result(doc)["fixes"] = [
            {"artifactChanges": [
                {"artifactLocation": {"uri": "a.py"}, "replacements": [{"x": 1}]}
            ]}
        ]
        self.assertIn("SRF-024", codes(scan_doc(doc)))

    def test_replacement_with_inserted_content_does_not_fire(self):
        doc = base_doc()
        base_result(doc)["fixes"] = [
            {"artifactChanges": [
                {"artifactLocation": {"uri": "a.py"},
                 "replacements": [{"deletedRegion": {"startLine": 1},
                                   "insertedContent": {"text": "x"}}]}
            ]}
        ]
        self.assertNotIn("SRF-024", codes(scan_doc(doc)))

    def test_replacement_with_only_deleted_region_does_not_fire(self):
        doc = base_doc()
        base_result(doc)["fixes"] = [
            {"artifactChanges": [
                {"artifactLocation": {"uri": "a.py"},
                 "replacements": [{"deletedRegion": {"startLine": 1}}]}
            ]}
        ]
        self.assertNotIn("SRF-024", codes(scan_doc(doc)))

    def test_location_without_physical_or_logical_fires(self):
        doc = base_doc()
        base_result(doc)["locations"] = [{"id": 1}]
        self.assertIn("SRF-024", codes(scan_doc(doc)))

    def test_location_with_logical_locations_does_not_fire(self):
        doc = base_doc()
        base_result(doc)["locations"] = [
            {"logicalLocations": [{"fullyQualifiedName": "a.b.c"}]}
        ]
        self.assertNotIn("SRF-024", codes(scan_doc(doc)))

    def test_base_document_does_not_fire(self):
        self.assertNotIn("SRF-024", codes(scan_doc(base_doc())))

    def test_message_does_not_predict_a_crash(self):
        doc = base_doc()
        base_result(doc)["locations"] = [{"id": 1}]
        message = messages_for(scan_doc(doc), "SRF-024")[0].lower()
        self.assertIn("has tripped", message)
        self.assertNotIn("will crash", message)

    def test_disable(self):
        doc = base_doc()
        base_result(doc)["locations"] = [{"id": 1}]
        self.assertNotIn("SRF-024", codes(scan_doc(doc, disabled=["SRF-024"])))


class Srf025TokenShapeTests(unittest.TestCase):
    # Assembled at runtime from sub-16-character parts so no committed file in
    # this repository carries a verbatim credential-shaped literal.
    TOKEN = "".join(("8Xk2vJ9pQ3wRnT5", "yBz7cLmD4hG6sVa", "0F1eU8oPiY2rXc"))

    def with_token(self):
        doc = base_doc()
        base_result(doc)["message"] = {"text": "saw value " + self.TOKEN + " here"}
        return doc

    def test_token_shape_fires(self):
        self.assertIn("SRF-025", codes(scan_doc(self.with_token())))

    def test_prose_does_not_fire(self):
        self.assertNotIn("SRF-025", codes(scan_doc(base_doc())))

    def test_message_never_reprints_the_match(self):
        message = messages_for(scan_doc(self.with_token()), "SRF-025")[0]
        self.assertNotIn(self.TOKEN, message)
        self.assertNotIn(self.TOKEN[:20], message)

    def test_message_reports_offset_and_length(self):
        message = messages_for(scan_doc(self.with_token()), "SRF-025")[0]
        self.assertIn("offset", message)
        self.assertIn("length " + str(len(self.TOKEN)), message)

    def test_message_refuses_the_secret_framing(self):
        message = messages_for(scan_doc(self.with_token()), "SRF-025")[0].lower()
        self.assertIn("token-shaped", message)
        self.assertNotIn("secret found", message)

    def test_severity_is_info(self):
        self.assertEqual(
            severity_of(scan_doc(self.with_token()), "SRF-025"), {Severity.INFO}
        )

    def test_disable(self):
        self.assertNotIn(
            "SRF-025", codes(scan_doc(self.with_token(), disabled=["SRF-025"]))
        )


class Srf026MetadataTests(unittest.TestCase):
    def test_missing_semantic_version_fires(self):
        doc = base_doc()
        del doc["runs"][0]["tool"]["driver"]["semanticVersion"]
        self.assertIn("SRF-026", codes(scan_doc(doc)))

    def test_missing_provenance_fires(self):
        doc = base_doc()
        del base_run(doc)["versionControlProvenance"]
        self.assertIn("SRF-026", codes(scan_doc(doc)))

    def test_empty_run_fires(self):
        doc = base_doc()
        base_run(doc)["results"] = []
        doc["runs"][0]["tool"]["driver"]["rules"] = []
        props = props_for(scan_doc(doc), "SRF-026")
        self.assertIn("runs[0]", props)

    def test_complete_metadata_does_not_fire(self):
        self.assertNotIn("SRF-026", codes(scan_doc(base_doc())))

    def test_severity_is_info(self):
        doc = base_doc()
        del base_run(doc)["versionControlProvenance"]
        self.assertEqual(severity_of(scan_doc(doc), "SRF-026"), {Severity.INFO})

    def test_disable(self):
        doc = base_doc()
        del base_run(doc)["versionControlProvenance"]
        self.assertNotIn("SRF-026", codes(scan_doc(doc, disabled=["SRF-026"])))


class Srf027ExternalPropsTests(unittest.TestCase):
    def with_external(self):
        doc = base_doc()
        base_run(doc)["externalPropertyFileReferences"] = {
            "results": [{"location": {"uri": "sidecar.sarif-external-properties"}}]
        }
        return doc

    def test_external_refs_fire(self):
        self.assertIn("SRF-027", codes(scan_doc(self.with_external())))

    def test_scan_is_marked_partial(self):
        self.assertTrue(scan_doc(self.with_external()).partial)

    def test_base_document_is_not_partial(self):
        self.assertFalse(scan_doc(base_doc()).partial)

    def test_partial_is_set_even_when_the_rule_is_disabled(self):
        # The verdict consequence must not depend on rule enablement.
        result = scan_doc(self.with_external(), disabled=["SRF-027"])
        self.assertTrue(result.partial)
        self.assertNotIn("SRF-027", codes(result))

    def test_message_names_the_referenced_sections(self):
        self.assertIn("results", messages_for(scan_doc(self.with_external()), "SRF-027")[0])

    def test_severity_is_info(self):
        self.assertEqual(
            severity_of(scan_doc(self.with_external()), "SRF-027"), {Severity.INFO}
        )


class ProfileFilterTests(unittest.TestCase):
    def test_spec_profile_excludes_ingest_rules(self):
        doc = base_doc()
        del doc["$schema"]
        self.assertNotIn("SRF-003", codes(scan_doc(doc, profiles=["spec"])))

    def test_spec_profile_keeps_spec_rules(self):
        doc = base_doc()
        doc["version"] = "2.1"
        self.assertIn("SRF-001", codes(scan_doc(doc, profiles=["spec"])))

    def test_ingest_profile_excludes_spec_rules(self):
        doc = base_doc()
        doc["version"] = "2.1"
        self.assertNotIn("SRF-001", codes(scan_doc(doc, profiles=["ingest"])))

    def test_hygiene_profile_keeps_only_hygiene_rules(self):
        doc = base_doc()
        doc["version"] = "2.1"
        base_result(doc)["message"] = {"text": "in /home/devuser/a.py"}
        found = codes(scan_doc(doc, profiles=["hygiene"]))
        self.assertIn("SRF-006", found)
        self.assertNotIn("SRF-001", found)

    def test_every_profile_has_at_least_one_rule(self):
        for profile in ("spec", "ingest", "hygiene"):
            present = [r for r in ALL_RULES if r.profile.value == profile]
            self.assertTrue(present, profile)


class NonSarifInputTests(unittest.TestCase):
    def test_wrong_top_level_type_is_an_error_not_a_traceback(self):
        result = scan_doc([1, 2, 3])
        self.assertTrue(result.errors)
        self.assertIn("not an object", result.errors[0])

    def test_object_without_runs_is_an_error(self):
        result = scan_doc({"version": "2.1.0"})
        self.assertTrue(result.errors)
        self.assertIn("'runs'", result.errors[0])

    def test_runs_of_the_wrong_type_is_an_error(self):
        result = scan_doc({"version": "2.1.0", "runs": {}})
        self.assertTrue(result.errors)

    def test_run_entries_of_the_wrong_type_do_not_crash(self):
        result = scan_doc({"version": "2.1.0", "runs": ["not-an-object", 7]})
        self.assertEqual(result.errors, ())

    def test_results_of_the_wrong_type_do_not_crash(self):
        result = scan_doc({"version": "2.1.0", "runs": [{"results": "nope"}]})
        self.assertEqual(result.errors, ())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
