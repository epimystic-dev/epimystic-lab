"""Per-rule behaviour: what fires, what must not fire, and what a disable does.

Every assertion is anchored to a rule id produced from an input, never to an
internal helper. Each rule has at least one positive case and one
false-positive guard.
"""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nbfactory as F  # noqa: E402

from nbshape.parse import build_notebook, prepare_cell  # noqa: E402
from nbshape.rules import (  # noqa: E402
    ALL_RULES,
    RULES_BY_ID,
    RuleConfig,
    RuleContext,
    run_rules,
    shannon_entropy,
)
from nbshape.types import Severity  # noqa: E402


def scan(obj, disabled=frozenset(), config=None, file_bytes=None):
    """Run the rule table over an in-memory notebook. Returns (codes, findings, gated)."""
    text = json.dumps(obj, indent=1, ensure_ascii=False)
    size = file_bytes if file_bytes is not None else len(text.encode("utf-8"))
    view = build_notebook(obj, file_bytes=size)
    codes = tuple(prepare_cell(c) for c in view.cells if c.is_code)
    ctx = RuleContext(
        nb=view,
        text=text,
        path="mem.ipynb",
        codes=codes,
        config=config if config is not None else RuleConfig(),
    )
    findings, gated = run_rules(ctx, disabled=disabled)
    return sorted({f.rule_id for f in findings}), findings, gated


def ids(obj, **kw):
    return scan(obj, **kw)[0]


class RegistryTests(unittest.TestCase):
    def test_every_rule_id_uses_the_nbk_prefix(self):
        for r in ALL_RULES:
            self.assertTrue(r.id.startswith("NBK-"), r.id)

    def test_rule_ids_are_zero_padded_three_digit_codes(self):
        for r in ALL_RULES:
            self.assertRegex(r.id, r"^NBK-\d{3}$")

    def test_rule_ids_are_unique(self):
        self.assertEqual(len({r.id for r in ALL_RULES}), len(ALL_RULES))

    def test_rule_ids_are_contiguous_from_001(self):
        want = ["NBK-" + str(i).zfill(3) for i in range(1, len(ALL_RULES) + 1)]
        self.assertEqual([r.id for r in ALL_RULES], want)

    def test_at_least_eight_distinct_rules_ship(self):
        self.assertGreaterEqual(len(ALL_RULES), 8)

    def test_every_rule_has_a_title_and_a_description(self):
        for r in ALL_RULES:
            self.assertTrue(r.title.strip(), r.id)
            self.assertTrue(r.description.strip(), r.id)

    def test_every_rule_carries_one_of_the_three_severities(self):
        for r in ALL_RULES:
            self.assertIn(r.severity, (Severity.HIGH, Severity.MEDIUM, Severity.INFO))

    def test_exactly_one_gate_rule_exists_and_it_is_nbk_010(self):
        gates = [r.id for r in ALL_RULES if r.gate]
        self.assertEqual(gates, ["NBK-010"])

    def test_the_gate_rule_is_always_visible(self):
        self.assertTrue(RULES_BY_ID["NBK-010"].always_visible)

    def test_rules_by_id_covers_the_whole_table(self):
        self.assertEqual(len(RULES_BY_ID), len(ALL_RULES))

    def test_no_rule_description_contains_a_non_ascii_character(self):
        for r in ALL_RULES:
            blob = r.id + r.title + r.description
            self.assertTrue(all(ord(ch) < 128 for ch in blob), r.id)


class Nbk001ExecutionOrderTests(unittest.TestCase):
    def test_a_lower_count_after_a_higher_one_fires(self):
        self.assertIn("NBK-001", ids(F.nb([
            F.code("a = 1", ec=1), F.code("b = 2", ec=5), F.code("c = 3", ec=3),
        ])))

    def test_a_strictly_increasing_sequence_does_not_fire(self):
        self.assertNotIn("NBK-001", ids(F.nb([
            F.code("a = 1", ec=1), F.code("b = 2", ec=2), F.code("c = 3", ec=3),
        ])))

    def test_a_gap_in_an_increasing_sequence_does_not_fire(self):
        self.assertNotIn("NBK-001", ids(F.nb([
            F.code("a = 1", ec=2), F.code("b = 2", ec=9),
        ])))

    def test_nulls_are_dropped_rather_than_treated_as_an_inversion(self):
        self.assertNotIn("NBK-001", ids(F.nb([
            F.code("a = 1", ec=1), F.code("b = 2", ec=None), F.code("c = 3", ec=4),
        ])))

    def test_a_notebook_with_zero_code_cells_does_not_fire(self):
        self.assertNotIn("NBK-001", ids(F.nb([F.markdown("hi")])))

    def test_a_single_code_cell_does_not_fire(self):
        self.assertNotIn("NBK-001", ids(F.nb([F.code("a = 1", ec=7)])))

    def test_all_null_counts_do_not_fire(self):
        self.assertNotIn("NBK-001", ids(F.nb([
            F.code("a = 1", ec=None), F.code("b = 2", ec=None),
        ])))

    def test_the_message_names_the_first_inverted_cell_index(self):
        _codes, findings, _g = scan(F.nb([
            F.code("a", ec=1), F.code("b", ec=2), F.code("c", ec=9), F.code("d", ec=4),
        ]))
        msg = [f.message for f in findings if f.rule_id == "NBK-001"][0]
        self.assertIn("cell 3", msg)

    def test_the_message_counts_multiple_inversions(self):
        _codes, findings, _g = scan(F.nb([
            F.code("a", ec=9), F.code("b", ec=1), F.code("c", ec=8), F.code("d", ec=2),
        ]))
        msg = [f.message for f in findings if f.rule_id == "NBK-001"][0]
        self.assertIn("2 inversions", msg)

    def test_severity_is_medium_not_high(self):
        self.assertEqual(RULES_BY_ID["NBK-001"].severity, Severity.MEDIUM)


class Nbk002OrphanOutputTests(unittest.TestCase):
    def test_outputs_with_a_null_count_fire(self):
        self.assertIn("NBK-002", ids(F.nb([
            F.code("print(1)", ec=None, outputs=[F.stream("1\n")]),
        ])))

    def test_outputs_with_a_real_count_do_not_fire(self):
        self.assertNotIn("NBK-002", ids(F.nb([
            F.code("print(1)", ec=1, outputs=[F.stream("1\n")]),
        ])))

    def test_a_null_count_with_no_outputs_does_not_fire(self):
        self.assertNotIn("NBK-002", ids(F.nb([F.code("print(1)", ec=None)])))

    def test_a_markdown_cell_never_fires_this_rule(self):
        self.assertNotIn("NBK-002", ids(F.nb([F.markdown("text")])))

    def test_severity_is_high(self):
        self.assertEqual(RULES_BY_ID["NBK-002"].severity, Severity.HIGH)


class Nbk003DuplicateCountsTests(unittest.TestCase):
    def test_two_cells_sharing_a_counter_fire(self):
        self.assertIn("NBK-003", ids(F.nb([
            F.code("a", ec=1), F.code("b", ec=2), F.code("c", ec=2),
        ])))

    def test_distinct_counters_do_not_fire(self):
        self.assertNotIn("NBK-003", ids(F.nb([
            F.code("a", ec=1), F.code("b", ec=2),
        ])))

    def test_two_null_counters_do_not_fire(self):
        self.assertNotIn("NBK-003", ids(F.nb([
            F.code("a", ec=None), F.code("b", ec=None),
        ])))

    def test_the_message_names_both_colliding_cells(self):
        _c, findings, _g = scan(F.nb([F.code("a", ec=4), F.code("b", ec=4)]))
        msg = [f.message for f in findings if f.rule_id == "NBK-003"][0]
        self.assertIn("cells 0 and 1", msg)


class Nbk004CounterOverrunTests(unittest.TestCase):
    def test_a_counter_far_past_the_cell_count_fires(self):
        self.assertIn("NBK-004", ids(F.nb([F.code("a", ec=1), F.code("b", ec=9)])))

    def test_a_counter_at_the_cell_count_does_not_fire(self):
        self.assertNotIn("NBK-004", ids(F.nb([
            F.code("a", ec=1), F.code("b", ec=2), F.code("c", ec=3),
        ])))

    def test_a_counter_exactly_at_the_factor_boundary_does_not_fire(self):
        self.assertNotIn("NBK-004", ids(F.nb([F.code("a", ec=1), F.code("b", ec=4)])))

    def test_raising_the_factor_silences_it(self):
        book = F.nb([F.code("a", ec=1), F.code("b", ec=9)])
        self.assertNotIn("NBK-004", ids(book, config=RuleConfig(rerun_factor=10.0)))

    def test_all_null_counts_do_not_fire(self):
        self.assertNotIn("NBK-004", ids(F.nb([F.code("a", ec=None)])))

    def test_severity_is_info_because_iteration_produces_this_normally(self):
        self.assertEqual(RULES_BY_ID["NBK-004"].severity, Severity.INFO)

    def test_the_message_disclaims_a_causal_reading(self):
        _c, findings, _g = scan(F.nb([F.code("a", ec=1), F.code("b", ec=9)]))
        msg = [f.message for f in findings if f.rule_id == "NBK-004"][0]
        self.assertIn("not a defect", msg)


class Nbk005LocalPathTests(unittest.TestCase):
    def test_a_windows_drive_path_fires(self):
        self.assertIn("NBK-005", ids(F.nb([F.code('p = "D:/lab/raw.csv"', ec=1)])))

    def test_a_backslash_drive_path_fires(self):
        self.assertIn("NBK-005", ids(F.nb([
            F.code('p = "C:\\\\Users\\\\jsmith\\\\raw.csv"', ec=1),
        ])))

    def test_a_home_directory_path_fires(self):
        self.assertIn("NBK-005", ids(F.nb([
            F.code('p = "/home/jsmith/data.csv"', ec=1),
        ])))

    def test_a_macos_users_path_fires(self):
        self.assertIn("NBK-005", ids(F.nb([
            F.code('p = "/Users/jsmith/data.csv"', ec=1),
        ])))

    def test_a_mount_point_path_fires(self):
        self.assertIn("NBK-005", ids(F.nb([F.code('p = "/mnt/bigdisk/x"', ec=1)])))

    def test_a_relative_path_does_not_fire(self):
        self.assertNotIn("NBK-005", ids(F.nb([F.code('p = "data/train.csv"', ec=1)])))

    def test_an_https_url_does_not_fire(self):
        self.assertNotIn("NBK-005", ids(F.nb([
            F.code('u = "https://example.com/data.csv"', ec=1),
        ])))

    def test_a_placeholder_home_path_does_not_fire(self):
        self.assertNotIn("NBK-005", ids(F.nb([
            F.code('p = "/home/user/notes.txt"', ec=1),
        ])))

    def test_the_generic_mnt_data_mount_does_not_fire(self):
        self.assertNotIn("NBK-005", ids(F.nb([F.code('p = "/mnt/data/x"', ec=1)])))

    def test_a_markdown_cell_is_not_scanned_for_paths(self):
        self.assertNotIn("NBK-005", ids(F.nb([
            F.markdown("Put your data in C:/Users/jsmith/data"),
        ])))

    def test_a_colab_mount_routes_to_nbk_016_not_nbk_005(self):
        codes = ids(F.nb([F.code('p = "/content/drive/MyDrive/x.csv"', ec=1)]))
        self.assertIn("NBK-016", codes)
        self.assertNotIn("NBK-005", codes)


class Nbk006CredentialShapeTests(unittest.TestCase):
    def test_a_credential_named_binding_with_a_long_literal_fires(self):
        self.assertIn("NBK-006", ids(F.nb([
            F.code('api_key = "' + F.CRED_VALUE + '"', ec=1),
        ])))

    def test_a_password_binding_fires(self):
        self.assertIn("NBK-006", ids(F.nb([
            F.code('password = "' + F.CRED_VALUE + '"', ec=1),
        ])))

    def test_a_keyword_argument_fires(self):
        self.assertIn("NBK-006", ids(F.nb([
            F.code('client = Thing(api_key="' + F.CRED_VALUE + '")', ec=1),
        ])))

    def test_a_dict_literal_key_fires(self):
        self.assertIn("NBK-006", ids(F.nb([
            F.code('cfg = {"access_key": "' + F.CRED_VALUE + '"}', ec=1),
        ])))

    def test_an_environment_lookup_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code('import os\napi_key = os.environ["DEMO_KEY"]', ec=1),
        ])))

    def test_an_angle_bracket_placeholder_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code('token = "<your-token-here>"', ec=1),
        ])))

    def test_a_changeme_placeholder_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([F.code('password = "changeme"', ec=1)])))

    def test_a_short_literal_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([F.code('token = "abc123"', ec=1)])))

    def test_a_non_credential_name_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code('caption = "' + F.CRED_VALUE + '"', ec=1),
        ])))

    def test_a_sentence_bound_to_a_credential_name_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code('secret = "this is a plain english sentence not a token"', ec=1),
        ])))

    def test_a_config_path_bound_to_a_credential_name_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code('secret_path = "config/settings/local/creds.yaml"', ec=1),
        ])))

    def test_a_high_entropy_token_in_a_stream_output_fires(self):
        self.assertIn("NBK-006", ids(F.nb([
            F.code("print(handle)", ec=1,
                   outputs=[F.stream("handle " + F.ENTROPY_TOKEN + "\n")]),
        ])))

    def test_a_high_entropy_token_in_text_plain_fires(self):
        self.assertIn("NBK-006", ids(F.nb([
            F.code("handle", ec=1,
                   outputs=[F.exec_result("'" + F.ENTROPY_TOKEN + "'", 1)]),
        ])))

    def test_a_base64_png_payload_is_never_entropy_scanned(self):
        blob = F.ENTROPY_TOKEN * 60
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code("plot()", ec=1, outputs=[F.display("image/png", blob)]),
        ])))

    def test_a_base64_jpeg_payload_is_never_entropy_scanned(self):
        blob = F.ENTROPY_TOKEN * 60
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code("plot()", ec=1, outputs=[F.display("image/jpeg", blob)]),
        ])))

    def test_a_pdf_payload_is_never_entropy_scanned(self):
        blob = F.ENTROPY_TOKEN * 60
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code("save()", ec=1, outputs=[F.display("application/pdf", blob)]),
        ])))

    def test_a_forty_character_git_sha_in_output_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code("print(sha)", ec=1,
                   outputs=[F.stream("9f2c1ab4de7856bc90ff12ab34cd56ef78901234\n")]),
        ])))

    def test_a_long_run_of_digits_in_output_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code("print(n)", ec=1, outputs=[F.stream("1" * 60 + "\n")]),
        ])))

    def test_a_long_lowercase_word_in_output_does_not_fire(self):
        self.assertNotIn("NBK-006", ids(F.nb([
            F.code("print(w)", ec=1, outputs=[F.stream("a" * 60 + "\n")]),
        ])))

    def test_the_finding_message_never_echoes_the_literal(self):
        _c, findings, _g = scan(F.nb([
            F.code('api_key = "' + F.CRED_VALUE + '"', ec=1),
        ]))
        for f in findings:
            if f.rule_id == "NBK-006":
                self.assertNotIn(F.CRED_VALUE, f.message)
                self.assertNotIn(F.CRED_VALUE, f.snippet)

    def test_the_message_says_shape_not_verified_secret(self):
        _c, findings, _g = scan(F.nb([
            F.code('api_key = "' + F.CRED_VALUE + '"', ec=1),
        ]))
        msg = [f.message for f in findings if f.rule_id == "NBK-006"][0]
        self.assertIn("not a verified secret", msg)

    def test_raising_the_minimum_length_silences_a_short_literal(self):
        book = F.nb([F.code('api_key = "' + F.CRED_VALUE + '"', ec=1)])
        self.assertNotIn("NBK-006", ids(book, config=RuleConfig(min_literal_len=500)))

    def test_a_credential_literal_in_an_unparseable_cell_still_fires_textually(self):
        src = '%%writefile cfg.py\napi_key = "' + F.CRED_VALUE + '"'
        self.assertIn("NBK-006", ids(F.nb([F.code(src, ec=1)])))


class EntropyTests(unittest.TestCase):
    def test_entropy_of_an_empty_string_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_entropy_of_a_single_repeated_character_is_zero(self):
        self.assertEqual(shannon_entropy("aaaaaa"), 0.0)

    def test_entropy_of_a_two_symbol_balanced_string_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0, places=6)

    def test_a_varied_token_scores_above_the_default_threshold(self):
        self.assertGreater(shannon_entropy(F.ENTROPY_TOKEN), 3.8)


class Nbk007UnpinnedInstallTests(unittest.TestCase):
    def test_a_bare_pip_install_fires(self):
        self.assertIn("NBK-007", ids(F.nb([F.code("!pip install pandas", ec=1)])))

    def test_a_percent_pip_install_fires(self):
        self.assertIn("NBK-007", ids(F.nb([F.code("%pip install pandas", ec=1)])))

    def test_a_python_dash_m_pip_install_fires(self):
        self.assertIn("NBK-007", ids(F.nb([
            F.code("!python -m pip install pandas", ec=1),
        ])))

    def test_a_double_equals_pin_does_not_fire(self):
        self.assertNotIn("NBK-007", ids(F.nb([
            F.code("!pip install pandas==2.1.0", ec=1),
        ])))

    def test_a_requirements_file_reference_does_not_fire(self):
        self.assertNotIn("NBK-007", ids(F.nb([
            F.code("!pip install -r requirements.txt", ec=1),
        ])))

    def test_a_constraints_file_reference_does_not_fire(self):
        self.assertNotIn("NBK-007", ids(F.nb([
            F.code("!pip install -c constraints.txt pandas", ec=1),
        ])))

    def test_a_git_url_does_not_fire(self):
        self.assertNotIn("NBK-007", ids(F.nb([
            F.code("!pip install git+https://example.com/pkg.git@abc123", ec=1),
        ])))

    def test_a_local_editable_install_does_not_fire(self):
        self.assertNotIn("NBK-007", ids(F.nb([F.code("!pip install -e .", ec=1)])))

    def test_quiet_flags_are_not_mistaken_for_packages(self):
        self.assertNotIn("NBK-007", ids(F.nb([
            F.code("!pip install -q --no-cache-dir pandas==2.1.0", ec=1),
        ])))

    def test_a_conda_single_equals_pin_does_not_fire(self):
        self.assertNotIn("NBK-007", ids(F.nb([
            F.code("!conda install numpy=1.26", ec=1),
        ])))

    def test_the_string_pip_install_inside_python_source_does_not_fire(self):
        self.assertNotIn("NBK-007", ids(F.nb([
            F.code('doc = "run pip install pandas first"', ec=1),
        ])))

    def test_a_bare_pip_line_inside_a_bash_cell_magic_fires(self):
        self.assertIn("NBK-007", ids(F.nb([
            F.code("%%bash\npip install pandas", ec=1),
        ])))


class Nbk008MissingSeedTests(unittest.TestCase):
    def test_numpy_sampling_without_a_seed_fires(self):
        self.assertIn("NBK-008", ids(F.nb([
            F.code("import numpy as np\nx = np.random.rand(10)", ec=1),
        ])))

    def test_stdlib_random_without_a_seed_fires(self):
        self.assertIn("NBK-008", ids(F.nb([
            F.code("import random\nx = random.randint(0, 9)", ec=1),
        ])))

    def test_torch_rand_without_a_seed_fires(self):
        self.assertIn("NBK-008", ids(F.nb([F.code("x = torch.randn(3)", ec=1)])))

    def test_a_shuffling_dataloader_without_a_seed_fires(self):
        self.assertIn("NBK-008", ids(F.nb([
            F.code("loader = DataLoader(ds, batch_size=32, shuffle=True)", ec=1),
        ])))

    def test_train_test_split_without_random_state_fires(self):
        self.assertIn("NBK-008", ids(F.nb([
            F.code("a, b = train_test_split(X, y, test_size=0.2)", ec=1),
        ])))

    def test_train_test_split_with_random_state_does_not_fire(self):
        self.assertNotIn("NBK-008", ids(F.nb([
            F.code("a, b = train_test_split(X, y, random_state=0)", ec=1),
        ])))

    def test_a_numpy_seed_in_an_earlier_cell_silences_it(self):
        self.assertNotIn("NBK-008", ids(F.nb([
            F.code("import numpy as np\nnp.random.seed(0)", ec=1),
            F.code("x = np.random.rand(10)", ec=2),
        ])))

    def test_a_torch_manual_seed_silences_it(self):
        self.assertNotIn("NBK-008", ids(F.nb([
            F.code("torch.manual_seed(0)\nx = torch.randn(3)", ec=1),
        ])))

    def test_seed_everything_silences_it(self):
        self.assertNotIn("NBK-008", ids(F.nb([
            F.code("seed_everything(7)\nx = torch.randn(3)", ec=1),
        ])))

    def test_default_rng_with_a_seed_does_not_fire(self):
        self.assertNotIn("NBK-008", ids(F.nb([
            F.code("rng = np.random.default_rng(42)\nx = rng.random(3)", ec=1),
        ])))

    def test_default_rng_with_no_seed_fires(self):
        self.assertIn("NBK-008", ids(F.nb([
            F.code("rng = np.random.default_rng()", ec=1),
        ])))

    def test_deterministic_torch_calls_are_not_treated_as_sampling(self):
        self.assertNotIn("NBK-008", ids(F.nb([
            F.code("t = torch.tensor([1, 2])\nm = torch.nn.Linear(2, 2)\n"
                   "w = torch.load('w.pt')", ec=1),
        ])))

    def test_a_notebook_with_no_sampling_at_all_does_not_fire(self):
        self.assertNotIn("NBK-008", ids(F.nb([F.code("x = 1 + 1", ec=1)])))

    def test_it_fires_at_most_once_per_notebook(self):
        _c, findings, _g = scan(F.nb([
            F.code("a = np.random.rand(3)", ec=1),
            F.code("b = np.random.rand(3)", ec=2),
            F.code("c = random.shuffle(z)", ec=3),
        ]))
        self.assertEqual(len([f for f in findings if f.rule_id == "NBK-008"]), 1)

    def test_the_message_admits_that_indirect_seeding_is_invisible(self):
        _c, findings, _g = scan(F.nb([F.code("x = np.random.rand(3)", ec=1)]))
        msg = [f.message for f in findings if f.rule_id == "NBK-008"][0]
        self.assertIn("not evidence of non-determinism", msg)


class Nbk009KernelMetadataTests(unittest.TestCase):
    def test_an_absent_language_info_fires(self):
        self.assertIn("NBK-009", ids(F.nb(
            [F.code("x = 1", ec=1)],
            metadata={"kernelspec": {"language": "python", "name": "python3"}},
        )))

    def test_an_absent_kernelspec_fires(self):
        self.assertIn("NBK-009", ids(F.nb(
            [F.code("x = 1", ec=1)],
            metadata={"language_info": {"name": "python", "version": "3.11.4"}},
        )))

    def test_empty_metadata_fires(self):
        self.assertIn("NBK-009", ids(F.nb([F.code("x = 1", ec=1)], metadata={})))

    def test_a_language_name_disagreeing_with_kernelspec_language_fires(self):
        self.assertIn("NBK-009", ids(F.nb(
            [F.code("x = 1", ec=1)],
            metadata={
                "kernelspec": {"language": "python", "name": "python3"},
                "language_info": {"name": "julia", "version": "1.10.0"},
            },
        )))

    def test_a_python_major_version_disagreeing_with_the_kernel_name_fires(self):
        self.assertIn("NBK-009", ids(F.nb(
            [F.code("x = 1", ec=1)],
            metadata={
                "kernelspec": {"language": "python", "name": "python3"},
                "language_info": {"name": "python", "version": "2.7.18"},
            },
        )))

    def test_a_coherent_pair_does_not_fire(self):
        self.assertNotIn("NBK-009", ids(F.nb([F.code("x = 1", ec=1)])))

    def test_a_non_python_kernel_name_skips_the_weak_version_inference(self):
        self.assertNotIn("NBK-009", ids(F.nb(
            [F.code("x = 1", ec=1)],
            metadata={
                "kernelspec": {"language": "julia", "name": "julia-1.10"},
                "language_info": {"name": "julia", "version": "1.10.0"},
            },
        )))

    def test_a_case_difference_alone_does_not_fire(self):
        self.assertNotIn("NBK-009", ids(F.nb(
            [F.code("x = 1", ec=1)],
            metadata={
                "kernelspec": {"language": "Python", "name": "python3"},
                "language_info": {"name": "python", "version": "3.11.4"},
            },
        )))

    def test_the_weak_version_message_says_the_inference_is_weak(self):
        _c, findings, _g = scan(F.nb(
            [F.code("x = 1", ec=1)],
            metadata={
                "kernelspec": {"language": "python", "name": "python3"},
                "language_info": {"name": "python", "version": "2.7.18"},
            },
        ))
        msgs = " ".join(f.message for f in findings if f.rule_id == "NBK-009")
        self.assertIn("weak", msgs)


class Nbk010GateTests(unittest.TestCase):
    def test_a_non_notebook_object_gates(self):
        codes, _f, gated = scan({"hello": "world"})
        self.assertEqual(codes, ["NBK-010"])
        self.assertTrue(gated)

    def test_the_gate_suppresses_every_other_rule(self):
        codes, _f, _g = scan({"cells": [{"cell_type": "code",
                                         "source": 'k = "/home/jsmith/x"',
                                         "execution_count": None,
                                         "outputs": [F.stream("x")]}]})
        self.assertEqual(codes, ["NBK-010"])

    def test_a_conformant_notebook_does_not_gate(self):
        codes, _f, gated = scan(F.nb([F.code("x = 1", ec=1)]))
        self.assertFalse(gated)
        self.assertNotIn("NBK-010", codes)

    def test_disabling_the_gate_rule_still_refuses_to_score_the_file(self):
        codes, _f, gated = scan({"hello": "world"}, disabled=frozenset(["NBK-010"]))
        self.assertTrue(gated)
        self.assertEqual(codes, [])


class Nbk011PayloadTests(unittest.TestCase):
    def test_a_payload_over_the_absolute_threshold_fires(self):
        book = F.nb([F.code("plot()", ec=1, outputs=[F.display("image/png", "A" * 5000)])])
        self.assertIn("NBK-011", ids(book, config=RuleConfig(max_output_bytes=1000)))

    def test_a_small_payload_under_the_threshold_does_not_fire(self):
        book = F.nb([F.code("plot()", ec=1, outputs=[F.display("image/png", "A" * 50)])])
        self.assertNotIn("NBK-011", ids(book))

    def test_text_output_is_never_counted_as_payload(self):
        book = F.nb([F.code("print(x)", ec=1, outputs=[F.stream("A" * 50000)])])
        self.assertNotIn("NBK-011", ids(book, config=RuleConfig(max_output_bytes=1000)))

    def test_the_relative_trigger_fires_on_a_payload_dominated_file(self):
        book = F.nb([F.code("plot()", ec=1, outputs=[F.display("image/png", "A" * 300000)])])
        self.assertIn("NBK-011", ids(book))

    def test_a_notebook_with_no_outputs_does_not_fire(self):
        self.assertNotIn("NBK-011", ids(F.nb([F.code("x = 1", ec=1)])))


class Nbk012HiddenStateTests(unittest.TestCase):
    def test_os_chdir_fires(self):
        self.assertIn("NBK-012", ids(F.nb([
            F.code("import os\nos.chdir('..')", ec=1),
        ])))

    def test_the_cd_magic_fires(self):
        self.assertIn("NBK-012", ids(F.nb([F.code("%cd ..", ec=1)])))

    def test_a_star_import_fires(self):
        self.assertIn("NBK-012", ids(F.nb([F.code("from numpy import *", ec=1)])))

    def test_deleting_a_name_bound_in_an_earlier_cell_fires(self):
        self.assertIn("NBK-012", ids(F.nb([
            F.code("results = [1, 2]", ec=1),
            F.code("del results", ec=2),
        ])))

    def test_deleting_a_name_bound_in_the_same_cell_does_not_fire(self):
        self.assertNotIn("NBK-012", ids(F.nb([
            F.code("temp = [1, 2]\ndel temp", ec=1),
        ])))

    def test_deleting_a_name_never_bound_in_the_notebook_does_not_fire(self):
        self.assertNotIn("NBK-012", ids(F.nb([F.code("del never_seen", ec=1)])))

    def test_a_named_import_does_not_fire(self):
        self.assertNotIn("NBK-012", ids(F.nb([
            F.code("from numpy import array", ec=1),
        ])))

    def test_a_path_join_does_not_fire(self):
        self.assertNotIn("NBK-012", ids(F.nb([
            F.code("import os\np = os.path.join('a', 'b')", ec=1),
        ])))

    def test_a_function_defined_then_deleted_across_cells_fires(self):
        self.assertIn("NBK-012", ids(F.nb([
            F.code("def helper():\n    return 1", ec=1),
            F.code("del helper", ec=2),
        ])))


class Nbk013CounterDisagreementTests(unittest.TestCase):
    def test_an_output_counter_disagreeing_with_its_cell_fires(self):
        self.assertIn("NBK-013", ids(F.nb([
            F.code("2 + 2", ec=3, outputs=[F.exec_result("4", 2)]),
            F.code("3 + 3", ec=4, outputs=[F.exec_result("6", 4)]),
        ])))

    def test_matching_counters_do_not_fire(self):
        self.assertNotIn("NBK-013", ids(F.nb([
            F.code("2 + 2", ec=3, outputs=[F.exec_result("4", 3)]),
        ])))

    def test_a_markdown_cell_carrying_an_execution_count_fires(self):
        self.assertIn("NBK-013", ids(F.nb([
            F.markdown("text", extra={"execution_count": 7}),
        ])))

    def test_a_markdown_cell_carrying_outputs_fires(self):
        self.assertIn("NBK-013", ids(F.nb([
            F.markdown("text", extra={"outputs": [F.stream("x")]}),
        ])))

    def test_a_markdown_cell_with_a_null_execution_count_does_not_fire(self):
        self.assertNotIn("NBK-013", ids(F.nb([
            F.markdown("text", extra={"execution_count": None}),
        ])))

    def test_a_markdown_cell_with_an_empty_outputs_array_does_not_fire(self):
        self.assertNotIn("NBK-013", ids(F.nb([
            F.markdown("text", extra={"outputs": []}),
        ])))

    def test_a_stream_output_has_no_counter_so_it_never_fires(self):
        self.assertNotIn("NBK-013", ids(F.nb([
            F.code("print(1)", ec=5, outputs=[F.stream("1\n")]),
        ])))


class Nbk014WidgetTests(unittest.TestCase):
    def _with(self, widgets):
        md = F.meta()
        md["widgets"] = widgets
        return F.nb([F.code("x = 1", ec=1)], metadata=md)

    def test_widgets_without_a_state_key_fire(self):
        self.assertIn("NBK-014", ids(self._with(
            {"application/vnd.jupyter.widget-state+json": {"version_major": 2}},
        )))

    def test_widgets_with_an_empty_state_fire(self):
        self.assertIn("NBK-014", ids(self._with(
            {"application/vnd.jupyter.widget-state+json": {"state": {}}},
        )))

    def test_widgets_with_a_populated_state_do_not_fire(self):
        self.assertNotIn("NBK-014", ids(self._with(
            {"application/vnd.jupyter.widget-state+json":
             {"state": {"abc": {"model_name": "LayoutModel"}}}},
        )))

    def test_a_widgets_value_that_is_not_an_object_fires(self):
        self.assertIn("NBK-014", ids(self._with("broken")))

    def test_absent_widgets_metadata_does_not_fire(self):
        self.assertNotIn("NBK-014", ids(F.nb([F.code("x = 1", ec=1)])))


class Nbk015CoverageDisclosureTests(unittest.TestCase):
    def test_a_shell_cell_magic_discloses_degraded_coverage(self):
        self.assertIn("NBK-015", ids(F.nb([F.code("%%bash\nls -la", ec=1)])))

    def test_a_syntax_error_cell_discloses_degraded_coverage(self):
        self.assertIn("NBK-015", ids(F.nb([F.code("def broken(\n", ec=1)])))

    def test_an_ordinary_cell_does_not_disclose(self):
        self.assertNotIn("NBK-015", ids(F.nb([F.code("x = 1", ec=1)])))

    def test_magics_alone_do_not_trigger_the_disclosure(self):
        self.assertNotIn("NBK-015", ids(F.nb([
            F.code("%matplotlib inline\n!ls\nimport os\nos.getcwd?", ec=1),
        ])))

    def test_an_empty_cell_does_not_trigger_the_disclosure(self):
        self.assertNotIn("NBK-015", ids(F.nb([F.code("", ec=1)])))

    def test_a_non_python_notebook_discloses_once_at_notebook_level(self):
        book = F.nb([F.code("x <- 1", ec=1), F.code("y <- 2", ec=2)], metadata={
            "kernelspec": {"language": "R", "name": "ir"},
            "language_info": {"name": "R", "version": "4.3.1"},
        })
        _c, findings, _g = scan(book)
        hits = [f for f in findings if f.rule_id == "NBK-015"]
        self.assertEqual(len(hits), 1)
        self.assertLess(hits[0].cell, 0)


class Nbk016HostedPathTests(unittest.TestCase):
    def test_a_content_path_fires(self):
        self.assertIn("NBK-016", ids(F.nb([
            F.code('p = "/content/sample_data/x.csv"', ec=1),
        ])))

    def test_a_drive_mount_path_fires(self):
        self.assertIn("NBK-016", ids(F.nb([
            F.code('p = "/content/drive/MyDrive/x.csv"', ec=1),
        ])))

    def test_a_kaggle_input_path_fires(self):
        self.assertIn("NBK-016", ids(F.nb([
            F.code('p = "/kaggle/input/titanic/train.csv"', ec=1),
        ])))

    def test_a_relative_path_does_not_fire(self):
        self.assertNotIn("NBK-016", ids(F.nb([F.code('p = "data/x.csv"', ec=1)])))

    def test_it_is_info_so_it_does_not_share_high_with_a_drive_letter_path(self):
        self.assertEqual(RULES_BY_ID["NBK-016"].severity, Severity.INFO)
        self.assertEqual(RULES_BY_ID["NBK-005"].severity, Severity.HIGH)


class Nbk017CellIdTests(unittest.TestCase):
    def test_a_missing_id_on_v4_5_fires(self):
        self.assertIn("NBK-017", ids(F.nb([F.code("x = 1", ec=1)], minor=5)))

    def test_a_duplicate_id_fires(self):
        self.assertIn("NBK-017", ids(F.nb([
            F.code("a", ec=1, cid="same"), F.code("b", ec=2, cid="same"),
        ], minor=5)))

    def test_a_malformed_id_fires(self):
        self.assertIn("NBK-017", ids(F.nb([
            F.code("a", ec=1, cid="has spaces and !"),
        ], minor=5)))

    def test_an_over_long_id_fires(self):
        self.assertIn("NBK-017", ids(F.nb([
            F.code("a", ec=1, cid="z" * 65),
        ], minor=5)))

    def test_unique_valid_ids_do_not_fire(self):
        self.assertNotIn("NBK-017", ids(F.nb([
            F.code("a", ec=1, cid="one"), F.code("b", ec=2, cid="two"),
        ], minor=5)))

    def test_a_v4_4_notebook_without_ids_does_not_fire(self):
        self.assertNotIn("NBK-017", ids(F.nb([F.code("x = 1", ec=1)], minor=4)))

    def test_a_v4_0_notebook_without_ids_does_not_fire(self):
        self.assertNotIn("NBK-017", ids(F.nb([F.code("x = 1", ec=1)], minor=0)))

    def test_markdown_cells_also_need_ids_on_v4_5(self):
        self.assertIn("NBK-017", ids(F.nb([
            F.code("a", ec=1, cid="one"), F.markdown("text"),
        ], minor=5)))


class Nbk018StrippedTests(unittest.TestCase):
    def test_a_fully_cleared_notebook_reports_the_cleared_state(self):
        self.assertIn("NBK-018", ids(F.nb([
            F.code("a = 1", ec=None), F.code("b = 2", ec=None),
        ])))

    def test_a_cleared_notebook_produces_no_ordering_finding(self):
        codes = ids(F.nb([
            F.code("a = 1", ec=None), F.code("b = 2", ec=None),
        ]))
        for banned in ("NBK-001", "NBK-002", "NBK-003", "NBK-004", "NBK-013"):
            self.assertNotIn(banned, codes)

    def test_a_cleared_notebook_is_only_info_so_it_scores_healthy(self):
        _c, findings, _g = scan(F.nb([F.code("a = 1", ec=None)]))
        self.assertTrue(all(f.severity == Severity.INFO for f in findings))

    def test_one_stored_output_means_it_is_not_cleared(self):
        self.assertNotIn("NBK-018", ids(F.nb([
            F.code("a = 1", ec=None, outputs=[F.stream("1\n")]),
        ])))

    def test_one_stored_counter_means_it_is_not_cleared(self):
        self.assertNotIn("NBK-018", ids(F.nb([
            F.code("a = 1", ec=1), F.code("b = 2", ec=None),
        ])))

    def test_a_notebook_with_no_code_cells_does_not_fire(self):
        self.assertNotIn("NBK-018", ids(F.nb([F.markdown("just prose")])))


class DisableTests(unittest.TestCase):
    """Every rule must be switchable off by its own id."""

    CASES = {
        "NBK-001": F.nb([F.code("a", ec=5), F.code("b", ec=1)]),
        "NBK-002": F.nb([F.code("a", ec=None, outputs=[F.stream("x")])]),
        "NBK-003": F.nb([F.code("a", ec=2), F.code("b", ec=2)]),
        "NBK-004": F.nb([F.code("a", ec=1), F.code("b", ec=9)]),
        "NBK-005": F.nb([F.code('p = "/home/jsmith/x"', ec=1)]),
        "NBK-006": F.nb([F.code('api_key = "' + F.CRED_VALUE + '"', ec=1)]),
        "NBK-007": F.nb([F.code("!pip install pandas", ec=1)]),
        "NBK-008": F.nb([F.code("x = np.random.rand(3)", ec=1)]),
        "NBK-009": F.nb([F.code("x = 1", ec=1)], metadata={}),
        "NBK-010": {"not": "a notebook"},
        "NBK-011": F.nb([F.code("p()", ec=1, outputs=[F.display("image/png", "A" * 300000)])]),
        "NBK-012": F.nb([F.code("import os\nos.chdir('..')", ec=1)]),
        "NBK-013": F.nb([F.markdown("t", extra={"execution_count": 3})]),
        "NBK-014": F.nb([F.code("x = 1", ec=1)], metadata=dict(
            F.meta(), widgets={"application/vnd.jupyter.widget-state+json": {}})),
        "NBK-015": F.nb([F.code("%%bash\nls", ec=1)]),
        "NBK-016": F.nb([F.code('p = "/content/x.csv"', ec=1)]),
        "NBK-017": F.nb([F.code("a", ec=1)], minor=5),
        "NBK-018": F.nb([F.code("a = 1", ec=None)]),
    }

    def test_every_rule_has_a_disable_case(self):
        self.assertEqual(sorted(self.CASES), sorted(r.id for r in ALL_RULES))

    def test_each_case_fires_its_own_rule_when_enabled(self):
        for rid, book in sorted(self.CASES.items()):
            with self.subTest(rule=rid):
                self.assertIn(rid, ids(book))

    def test_each_rule_is_absent_once_disabled(self):
        for rid, book in sorted(self.CASES.items()):
            with self.subTest(rule=rid):
                self.assertNotIn(rid, ids(book, disabled=frozenset([rid])))

    def test_disabling_one_rule_leaves_the_others_running(self):
        book = F.nb([
            F.code('p = "/home/jsmith/x"', ec=5),
            F.code("q = 1", ec=1),
        ])
        codes = ids(book, disabled=frozenset(["NBK-005"]))
        self.assertNotIn("NBK-005", codes)
        self.assertIn("NBK-001", codes)


if __name__ == "__main__":
    unittest.main()
