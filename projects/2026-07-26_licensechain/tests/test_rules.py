import json
import unittest

from licensechain.loader import load_manifest
from licensechain.rules import check_chain, Severity


def _run(m: dict):
    chain = load_manifest(json.dumps(m))
    return check_chain(chain)


def _has_rule(findings, rule):
    return any(f.rule == rule for f in findings)


def _rule_severity(findings, rule):
    for f in findings:
        if f.rule == rule:
            return f.severity
    return None


class Rule001MissingLicenseTests(unittest.TestCase):

    def test_missing_license_triggers_lic001_error(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-001"))
        self.assertEqual(_rule_severity(findings, "LIC-001"), Severity.ERROR)

    def test_present_license_does_not_trigger_lic001(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "MIT"},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-001"))

    def test_empty_string_license_triggers_lic001(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "   "},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-001"))


class Rule002UnknownIdTests(unittest.TestCase):

    def test_unknown_id_triggers_lic002_warn(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "Foobar-1.0"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-002"))
        self.assertEqual(_rule_severity(findings, "LIC-002"), Severity.WARN)

    def test_known_id_does_not_trigger_lic002(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "MIT"},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-002"))

    def test_lowercase_id_triggers_lic002_because_case_sensitive(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "mit"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-002"))


class Rule003ParseErrorTests(unittest.TestCase):

    def test_unparseable_expression_triggers_lic003(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "MIT AND"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-003"))
        self.assertEqual(_rule_severity(findings, "LIC-003"), Severity.ERROR)

    def test_parseable_expression_does_not_trigger_lic003(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application",
             "license": "MIT OR Apache-2.0"},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-003"))


class Rule004CopyleftDroppedTests(unittest.TestCase):

    def test_gpl_upstream_mit_downstream_triggers_lic004(self):
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "GPL-3.0-only", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "MIT", "uses": ["lib"], "preserves_notices": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-004"))

    def test_gpl_upstream_gpl_downstream_does_not_trigger_lic004(self):
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "GPL-3.0-only", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "GPL-3.0-only", "uses": ["lib"],
             "preserves_notices": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-004"))

    def test_agpl_upstream_mit_downstream_triggers_lic004(self):
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "AGPL-3.0-only", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "MIT", "uses": ["lib"], "preserves_notices": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-004"))


class Rule005NoticeObligationTests(unittest.TestCase):

    def test_apache_upstream_without_preserves_notices_triggers_lic005(self):
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library", "license": "Apache-2.0"},
            {"name": "app", "role": "application", "license": "MIT",
             "uses": ["lib"]},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-005"))
        self.assertEqual(_rule_severity(findings, "LIC-005"), Severity.WARN)

    def test_downstream_preserves_notices_true_suppresses_lic005(self):
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library", "license": "Apache-2.0"},
            {"name": "app", "role": "application", "license": "MIT",
             "uses": ["lib"], "preserves_notices": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-005"))

    def test_cc0_upstream_does_not_trigger_lic005(self):
        # CC0 has no notice obligation.
        findings = _run({"version": 1, "chain": [
            {"name": "data", "role": "dataset", "license": "CC0-1.0"},
            {"name": "app", "role": "application", "license": "MIT",
             "uses": ["data"]},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-005"))


class Rule006ShareAlikeTests(unittest.TestCase):

    def test_cc_by_sa_upstream_mit_downstream_triggers_lic006(self):
        findings = _run({"version": 1, "chain": [
            {"name": "data", "role": "dataset",
             "license": "CC-BY-SA-4.0", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "MIT", "trained_on": ["data"],
             "preserves_notices": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-006"))

    def test_cc_by_sa_upstream_same_downstream_does_not_trigger(self):
        findings = _run({"version": 1, "chain": [
            {"name": "data", "role": "dataset",
             "license": "CC-BY-SA-4.0", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "CC-BY-SA-4.0", "trained_on": ["data"],
             "preserves_notices": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-006"))

    def test_cdla_sharing_upstream_permissive_downstream_triggers(self):
        findings = _run({"version": 1, "chain": [
            {"name": "d", "role": "dataset",
             "license": "CDLA-Sharing-1.0", "preserves_notices": True},
            {"name": "m", "role": "model",
             "license": "Apache-2.0", "trained_on": ["d"],
             "preserves_notices": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-006"))


class Rule007IncompatibilityTests(unittest.TestCase):

    def test_no_derivatives_upstream_triggers_lic007(self):
        findings = _run({"version": 1, "chain": [
            {"name": "data", "role": "dataset",
             "license": "CC-BY-ND-4.0", "preserves_notices": True},
            {"name": "m", "role": "model",
             "license": "Apache-2.0", "trained_on": ["data"],
             "preserves_notices": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-007"))

    def test_use_restricted_upstream_permissive_downstream_triggers(self):
        findings = _run({"version": 1, "chain": [
            {"name": "m", "role": "model",
             "license": "OpenRAIL-M", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "MIT", "uses": ["m"], "preserves_notices": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-007"))

    def test_use_restricted_upstream_same_downstream_does_not_trigger(self):
        findings = _run({"version": 1, "chain": [
            {"name": "m", "role": "model",
             "license": "OpenRAIL-M", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "OpenRAIL-M", "uses": ["m"],
             "preserves_notices": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-007"))


class Rule008UnversionedTests(unittest.TestCase):

    def test_gpl_2_unversioned_triggers_lic008(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "GPL-2.0"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-008"))
        self.assertEqual(_rule_severity(findings, "LIC-008"), Severity.WARN)

    def test_gpl_2_only_does_not_trigger_lic008(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "GPL-2.0-only"},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-008"))

    def test_lgpl_3_unversioned_triggers_lic008(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "LGPL-3.0"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-008"))


class Rule009NoassertionTests(unittest.TestCase):

    def test_noassertion_triggers_lic009(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "NOASSERTION"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-009"))
        self.assertEqual(_rule_severity(findings, "LIC-009"), Severity.ERROR)

    def test_none_triggers_lic009(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "NONE"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-009"))

    def test_mit_does_not_trigger_lic009(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "MIT"},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-009"))


class Rule010LicenseRefTests(unittest.TestCase):

    def test_license_ref_triggers_lic010(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application",
             "license": "LicenseRef-InternalPolicy"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-010"))
        self.assertEqual(_rule_severity(findings, "LIC-010"), Severity.WARN)

    def test_plain_mit_does_not_trigger_lic010(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "MIT"},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-010"))


class Rule011NonCommercialTests(unittest.TestCase):

    def test_nc_upstream_commercial_downstream_triggers_lic011(self):
        findings = _run({"version": 1, "chain": [
            {"name": "d", "role": "dataset",
             "license": "CC-BY-NC-4.0", "preserves_notices": True},
            {"name": "m", "role": "model",
             "license": "CC-BY-NC-4.0", "trained_on": ["d"],
             "preserves_notices": True, "commercial_use": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-011"))
        self.assertEqual(_rule_severity(findings, "LIC-011"), Severity.ERROR)

    def test_nc_upstream_noncommercial_downstream_does_not_trigger(self):
        findings = _run({"version": 1, "chain": [
            {"name": "d", "role": "dataset",
             "license": "CC-BY-NC-4.0", "preserves_notices": True},
            {"name": "m", "role": "model",
             "license": "CC-BY-NC-4.0", "trained_on": ["d"],
             "preserves_notices": True, "commercial_use": False},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-011"))

    def test_permissive_upstream_commercial_downstream_does_not_trigger(self):
        findings = _run({"version": 1, "chain": [
            {"name": "d", "role": "dataset",
             "license": "CC-BY-4.0", "preserves_notices": True},
            {"name": "m", "role": "model",
             "license": "MIT", "trained_on": ["d"],
             "preserves_notices": True, "commercial_use": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-011"))


class Rule012OrphanTests(unittest.TestCase):

    def test_orphan_component_triggers_lic012_info(self):
        findings = _run({"version": 1, "chain": [
            {"name": "a", "role": "model", "license": "MIT"},
            {"name": "b", "role": "model", "license": "MIT"},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-012"))
        self.assertEqual(_rule_severity(findings, "LIC-012"), Severity.INFO)

    def test_connected_chain_does_not_trigger_lic012(self):
        findings = _run({"version": 1, "chain": [
            {"name": "d", "role": "dataset", "license": "CC0-1.0"},
            {"name": "m", "role": "model", "license": "MIT",
             "trained_on": ["d"], "preserves_notices": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-012"))


class OutputShapeTests(unittest.TestCase):

    def test_findings_have_finding_to_dict(self):
        findings = _run({"version": 1, "chain": [
            {"name": "app", "role": "application", "license": "MIT",
             "uses": ["lib"]},
            {"name": "lib", "role": "library", "license": "GPL-3.0-only",
             "preserves_notices": True},
        ]})
        for f in findings:
            d = f.to_dict()
            self.assertIn("rule", d)
            self.assertIn("severity", d)
            self.assertIn("component", d)
            self.assertIn("message", d)

    def test_findings_are_deterministically_ordered(self):
        m = {"version": 1, "chain": [
            {"name": "d", "role": "dataset",
             "license": "CC-BY-SA-4.0", "preserves_notices": True},
            {"name": "m", "role": "model",
             "license": "MIT", "trained_on": ["d"], "preserves_notices": True},
        ]}
        f1 = _run(m)
        f2 = _run(m)
        self.assertEqual([f.rule for f in f1], [f.rule for f in f2])
        self.assertEqual([f.message for f in f1], [f.message for f in f2])


class OrExpressionTests(unittest.TestCase):

    def test_or_expression_permits_compatible_choice(self):
        # Downstream "MIT OR GPL-3.0-only" against GPL-3.0-only upstream:
        # the GPL choice complies, so no LIC-004.
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "GPL-3.0-only", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "MIT OR GPL-3.0-only", "uses": ["lib"],
             "preserves_notices": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-004"))
        self.assertFalse(_has_rule(findings, "LIC-007"))

    def test_or_upstream_with_at_least_one_compatible_branch_is_clean(self):
        # Upstream "MIT OR GPL-3.0-only" -> downstream MIT: the MIT branch
        # of the upstream is compatible, so no LIC-004 should fire.
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "MIT OR GPL-3.0-only", "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "MIT", "uses": ["lib"], "preserves_notices": True},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-004"))
        self.assertFalse(_has_rule(findings, "LIC-007"))

    def test_or_upstream_where_all_branches_are_incompatible_fires(self):
        # Upstream "GPL-3.0-only OR AGPL-3.0-only" -> downstream MIT: no
        # compatible branch exists, LIC-004 fires.
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "GPL-3.0-only OR AGPL-3.0-only",
             "preserves_notices": True},
            {"name": "app", "role": "application",
             "license": "MIT", "uses": ["lib"], "preserves_notices": True},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-004"))

    def test_or_upstream_notice_only_fires_if_all_branches_require(self):
        # Upstream "MIT OR CC0-1.0" -> downstream MIT with no preserves-
        # notices: MIT requires notice, CC0 doesn't; the downstream could
        # legally pick CC0 -> no LIC-005 should fire.
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "MIT OR CC0-1.0"},
            {"name": "app", "role": "application",
             "license": "MIT", "uses": ["lib"]},
        ]})
        self.assertFalse(_has_rule(findings, "LIC-005"))

    def test_or_upstream_notice_fires_when_every_branch_requires(self):
        # Upstream "MIT OR Apache-2.0" -> downstream MIT, no preserves-
        # notices: both branches require notice, so LIC-005 fires.
        findings = _run({"version": 1, "chain": [
            {"name": "lib", "role": "library",
             "license": "MIT OR Apache-2.0"},
            {"name": "app", "role": "application",
             "license": "MIT", "uses": ["lib"]},
        ]})
        self.assertTrue(_has_rule(findings, "LIC-005"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
