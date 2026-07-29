import unittest

from licensechain.spdx_data import (
    LICENSES, is_known_id, get_license, is_downstream_compatible,
)


class KnownIdTests(unittest.TestCase):

    def test_common_permissive_ids_are_known(self):
        for i in ("MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
                  "ISC", "0BSD"):
            self.assertTrue(is_known_id(i), i)

    def test_gpl_family_ids_are_known(self):
        for i in ("GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only",
                  "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
                  "LGPL-2.1-only", "LGPL-3.0-only"):
            self.assertTrue(is_known_id(i), i)

    def test_cc_family_ids_are_known(self):
        for i in ("CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0",
                  "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0", "CC-BY-ND-4.0"):
            self.assertTrue(is_known_id(i), i)

    def test_data_licenses_are_known(self):
        for i in ("CDLA-Permissive-2.0", "CDLA-Sharing-1.0", "ODbL-1.0"):
            self.assertTrue(is_known_id(i), i)

    def test_rail_family_is_known(self):
        for i in ("OpenRAIL", "OpenRAIL-M", "RAIL"):
            self.assertTrue(is_known_id(i), i)

    def test_unknown_id_is_not_known(self):
        self.assertFalse(is_known_id("NotAReal-1.0"))

    def test_case_sensitivity_per_spec(self):
        # SPDX ids are case-sensitive; lowercase "mit" is not a match.
        self.assertFalse(is_known_id("mit"))
        self.assertTrue(is_known_id("MIT"))

    def test_get_license_raises_on_unknown(self):
        with self.assertRaises(KeyError):
            get_license("NotAReal-1.0")

    def test_noassertion_and_none_are_present_but_unknown_category(self):
        self.assertTrue(is_known_id("NOASSERTION"))
        self.assertTrue(is_known_id("NONE"))
        self.assertEqual(get_license("NOASSERTION").category, "unknown")


class CompatibilityTests(unittest.TestCase):

    def test_identity_is_always_compatible(self):
        for i in ("MIT", "GPL-3.0-only", "CC-BY-SA-4.0",
                  "CC-BY-NC-4.0"):
            ok, _reason = is_downstream_compatible(i, i)
            self.assertTrue(ok, i)

    def test_permissive_upstream_permissive_downstream(self):
        ok, _r = is_downstream_compatible("MIT", "Apache-2.0")
        self.assertTrue(ok)
        ok, _r = is_downstream_compatible("BSD-2-Clause", "MIT")
        self.assertTrue(ok)

    def test_public_domain_upstream_is_compatible_with_anything(self):
        for down in ("MIT", "GPL-3.0-only", "CC-BY-SA-4.0"):
            ok, _r = is_downstream_compatible("CC0-1.0", down)
            self.assertTrue(ok, down)

    def test_strong_copyleft_upstream_permissive_downstream_fails(self):
        ok, reason = is_downstream_compatible("GPL-3.0-only", "MIT")
        self.assertFalse(ok)
        self.assertIn("copyleft", reason)

    def test_gpl2_only_and_gpl3_only_are_not_compatible(self):
        # GPL-2.0-only is intentionally NOT compatible with GPL-3.0-only.
        ok, _r = is_downstream_compatible("GPL-2.0-only", "GPL-3.0-only")
        self.assertFalse(ok)

    def test_gpl2_or_later_upgrades_to_gpl3(self):
        ok, _r = is_downstream_compatible("GPL-2.0-or-later", "GPL-3.0-only")
        self.assertTrue(ok)
        ok, _r = is_downstream_compatible(
            "GPL-2.0-or-later", "GPL-3.0-or-later")
        self.assertTrue(ok)

    def test_gpl3_upgrades_to_agpl(self):
        ok, _r = is_downstream_compatible("GPL-3.0-only", "AGPL-3.0-only")
        self.assertTrue(ok)

    def test_share_alike_requires_same_license(self):
        ok, reason = is_downstream_compatible("CC-BY-SA-4.0", "MIT")
        self.assertFalse(ok)
        self.assertIn("same", reason)

    def test_no_derivatives_upstream_blocks_downstream(self):
        ok, reason = is_downstream_compatible("CC-BY-ND-4.0", "MIT")
        self.assertFalse(ok)
        self.assertIn("no-derivatives", reason)

    def test_non_commercial_upstream_blocks_commercial_downstream(self):
        ok, reason = is_downstream_compatible("CC-BY-NC-4.0", "MIT")
        self.assertFalse(ok)
        self.assertIn("commercial", reason)

    def test_non_commercial_upstream_permits_nc_downstream(self):
        ok, _r = is_downstream_compatible("CC-BY-NC-4.0", "CC-BY-NC-4.0")
        self.assertTrue(ok)
        ok, _r = is_downstream_compatible("CC-BY-NC-4.0", "CC-BY-NC-SA-4.0")
        # Different license, but both restrict commercial; still fails
        # LIC-006 share-alike check in rules, but the compatibility fn
        # only asks about commercial + shape.
        # Here we test the "restricts_commercial" branch alone:
        self.assertTrue(ok)

    def test_use_restricted_upstream_requires_use_restricted_downstream(self):
        ok, reason = is_downstream_compatible("OpenRAIL-M", "Apache-2.0")
        self.assertFalse(ok)
        self.assertIn("use restrictions", reason)
        ok, _r = is_downstream_compatible("OpenRAIL-M", "OpenRAIL-M")
        self.assertTrue(ok)

    def test_weak_copyleft_upstream_permissive_downstream_is_allowed(self):
        # Weak copyleft ships as library; permissive downstream is fine
        # provided source of the LGPL component is available (LIC-005 warns).
        ok, _r = is_downstream_compatible("LGPL-3.0-only", "MIT")
        self.assertTrue(ok)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
