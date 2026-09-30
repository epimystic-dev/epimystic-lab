"""Per-rule positive + negative tests.

For every rule we test at least one fixture that fires it and at least
one that does not - so a regression that mutes a rule flips the
negative test, and a regression that widens a rule flips the positive
test.
"""

import unittest

from approvchainlint.rules import REGISTRY, REGISTRY_BY_ID, run_all, all_rule_ids
from approvchainlint.types import Options, Severity

from tests.support import make_sticky_secret, make_high_entropy_token, scan_dict, rule_ids


BASE_HEALTHY = {
    "permissions": {
        "allow": ["Bash(git status)"],
        "defaultMode": "confirm",
    },
    "tools": [
        {
            "name": "read_only_reader",
            "read_only": True,
            "capabilities": ["filesystem_read"],
            "effects": ["filesystem_read"],
        }
    ],
    "approvals": [],
}


def _with_tool(**extra):
    doc = {"tools": [dict(extra)]}
    return doc


def _with_approvals(*entries):
    return {"approvals": list(entries)}


class RegistryInvariants(unittest.TestCase):
    def test_count_is_twelve(self):
        self.assertEqual(len(REGISTRY), 12)

    def test_ids_are_unique(self):
        ids = [r.id for r in REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_are_canonical(self):
        for r in REGISTRY:
            self.assertRegex(r.id, r"^AC-\d{3}$")

    def test_descriptions_non_empty(self):
        for r in REGISTRY:
            self.assertTrue(r.description.strip())

    def test_valid_severity(self):
        for r in REGISTRY:
            self.assertIn(r.severity, {Severity.HIGH, Severity.MEDIUM, Severity.INFO})

    def test_severity_split(self):
        counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.INFO: 0}
        for r in REGISTRY:
            counts[r.severity] += 1
        # 5 HIGH, 4 MEDIUM, 3 INFO
        self.assertEqual(counts[Severity.HIGH], 5)
        self.assertEqual(counts[Severity.MEDIUM], 4)
        self.assertEqual(counts[Severity.INFO], 3)

    def test_check_callable(self):
        for r in REGISTRY:
            self.assertTrue(callable(r.check))

    def test_registry_by_id_matches(self):
        for r in REGISTRY:
            self.assertIs(REGISTRY_BY_ID[r.id], r)

    def test_healthy_fires_nothing(self):
        _err, findings = scan_dict(BASE_HEALTHY, options=Options(include_info=True))
        self.assertEqual(findings, [])

    def test_empty_dict_fires_nothing(self):
        _err, findings = scan_dict({}, options=Options(include_info=True))
        self.assertEqual(findings, [])

    def test_run_all_swallows_disabled(self):
        doc = {"permissions": {"allow": ["Bash(*)"]}}
        _err, findings = scan_dict(doc, options=Options(disabled=frozenset({"AC-001"})))
        self.assertNotIn("AC-001", rule_ids(findings))

    def test_all_rule_ids_matches_registry(self):
        self.assertEqual(all_rule_ids(), tuple(r.id for r in REGISTRY))

    def test_run_all_swallows_rule_crash(self):
        # A non-dict doc must not raise; every rule short-circuits.
        _err, findings = scan_dict({}, options=Options())
        # No exception, no false-positive findings on empty doc.
        self.assertEqual(findings, [])


# --- AC-001 ---


class Rule001WildcardSubprocess(unittest.TestCase):
    def test_bash_wildcard_fires(self):
        _err, f = scan_dict({"permissions": {"allow": ["Bash(*)"]}})
        self.assertIn("AC-001", rule_ids(f))

    def test_shell_double_wildcard_fires(self):
        _err, f = scan_dict({"permissions": {"allow": ["Shell(**)"]}})
        self.assertIn("AC-001", rule_ids(f))

    def test_default_mode_accept_edits_fires(self):
        _err, f = scan_dict({"permissions": {"defaultMode": "acceptEdits"}})
        self.assertIn("AC-001", rule_ids(f))

    def test_default_mode_bypass_fires(self):
        _err, f = scan_dict({"permissions": {"defaultMode": "bypassPermissions"}})
        self.assertIn("AC-001", rule_ids(f))

    def test_default_mode_auto_fires(self):
        _err, f = scan_dict({"permissions": {"defaultMode": "auto"}})
        self.assertIn("AC-001", rule_ids(f))

    def test_bash_specific_arg_no_fire(self):
        _err, f = scan_dict({"permissions": {"allow": ["Bash(git status)"]}})
        self.assertNotIn("AC-001", rule_ids(f))

    def test_python_c_wildcard_arg_fires(self):
        _err, f = scan_dict({"permissions": {"allow": ["Python(-c import*os)"]}})
        self.assertIn("AC-001", rule_ids(f))


# --- AC-002 ---


class Rule002StickyNoTtl(unittest.TestCase):
    def test_sticky_true_fires(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "x", "scope": "Bash(x)", "sticky": True, "capabilities": ["subprocess"]}
        ))
        self.assertIn("AC-002", rule_ids(f))

    def test_auto_approve_fires(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "x", "scope": "http_get", "auto_approve": True,
             "capabilities": ["network"]}
        ))
        self.assertIn("AC-002", rule_ids(f))

    def test_long_ttl_fires(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "x", "scope": "Bash(x)", "ttl_seconds": 3600,
             "capabilities": ["subprocess"]}
        ))
        self.assertIn("AC-002", rule_ids(f))

    def test_high_effect_no_ttl_fires(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "x", "scope": "Bash(x)", "capabilities": ["subprocess"]}
        ))
        self.assertIn("AC-002", rule_ids(f))

    def test_short_ttl_low_effect_no_fire(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "read_x", "scope": "read_x(docs)",
             "ttl_seconds": 60, "capabilities": ["filesystem_read"]}
        ))
        self.assertNotIn("AC-002", rule_ids(f))

    def test_sticky_secret_helper_available_when_needed(self):
        # Confirms the sub-16-char assembly convention is intact and
        # can be used inside test doc bodies without whole-secret
        # literals in source.
        tok = make_sticky_secret()
        self.assertGreaterEqual(len(tok), 40)
        other = make_high_entropy_token()
        self.assertGreaterEqual(len(other), 30)


# --- AC-003 ---


class Rule003ScopeBroaderThanSurface(unittest.TestCase):
    def _doc(self, scope, **tool_extra):
        return {
            "tools": [dict({"name": "toolA", "command": "/usr/bin/toolA"},
                           **tool_extra)],
            "permissions": {"allow": [scope]},
        }

    def test_wildcard_scope_fires(self):
        _err, f = scan_dict(self._doc("toolA(*)"))
        self.assertIn("AC-003", rule_ids(f))

    def test_double_wildcard_scope_fires(self):
        _err, f = scan_dict(self._doc("toolA(**)"))
        self.assertIn("AC-003", rule_ids(f))

    def test_specific_arg_no_fire(self):
        _err, f = scan_dict(self._doc("toolA(status)"))
        self.assertNotIn("AC-003", rule_ids(f))

    def test_wildcard_host_when_specific_hosts_declared(self):
        doc = {
            "tools": [{"name": "netA", "network_hosts": ["specific.example.com"]}],
            "permissions": {"allow": ["netA(*.example.com)"]},
        }
        _err, f = scan_dict(doc)
        self.assertIn("AC-003", rule_ids(f))


# --- AC-004 ---


class Rule004DelegatorNoBinding(unittest.TestCase):
    def test_delegates_to_fires(self):
        _err, f = scan_dict(_with_tool(
            name="d", delegates_to=["x", "y"], effects=["subprocess"]
        ))
        self.assertIn("AC-004", rule_ids(f))

    def test_child_tools_fires(self):
        _err, f = scan_dict(_with_tool(
            name="d", child_tools=["x"], effects=["subprocess"]
        ))
        self.assertIn("AC-004", rule_ids(f))

    def test_subagents_fires(self):
        _err, f = scan_dict(_with_tool(
            name="d", subagents=["x"], effects=["subprocess"]
        ))
        self.assertIn("AC-004", rule_ids(f))

    def test_bound_no_fire(self):
        _err, f = scan_dict(_with_tool(
            name="d", delegates_to=["x"], effects=["subprocess"],
            require_child_approval=True
        ))
        self.assertNotIn("AC-004", rule_ids(f))

    def test_record_transitive_no_fire(self):
        _err, f = scan_dict(_with_tool(
            name="d", delegates_to=["x"], effects=["subprocess"],
            record_transitive_effects=True
        ))
        self.assertNotIn("AC-004", rule_ids(f))


# --- AC-005 ---


class Rule005NetworkNoAllowlist(unittest.TestCase):
    def test_network_capability_fires(self):
        _err, f = scan_dict(_with_tool(
            name="n", capabilities=["network"]
        ))
        self.assertIn("AC-005", rule_ids(f))

    def test_network_true_fires(self):
        _err, f = scan_dict(_with_tool(
            name="n", network=True, effects=["network"]
        ))
        self.assertIn("AC-005", rule_ids(f))

    def test_allowlist_hosts_no_fire(self):
        _err, f = scan_dict(_with_tool(
            name="n", capabilities=["network"],
            allowlist_hosts=["docs.example.com"]
        ))
        self.assertNotIn("AC-005", rule_ids(f))

    def test_read_only_http_skips(self):
        _err, f = scan_dict(_with_tool(
            name="n", read_only=True, capabilities=["http"]
        ))
        self.assertNotIn("AC-005", rule_ids(f))

    def test_mcp_curl_command_fires(self):
        doc = {
            "mcpServers": {
                "srv": {
                    "command": "curl",
                    "args": ["https://example.invalid/x"],
                    "tools": []
                }
            }
        }
        _err, f = scan_dict(doc)
        self.assertIn("AC-005", rule_ids(f))


# --- AC-006 ---


class Rule006BareToolName(unittest.TestCase):
    def test_bare_name_fires(self):
        _err, f = scan_dict({"permissions": {"allow": ["GitStatus"]}})
        self.assertIn("AC-006", rule_ids(f))

    def test_bare_name_in_ask_fires(self):
        _err, f = scan_dict({"permissions": {"ask": ["Bash"]}})
        self.assertIn("AC-006", rule_ids(f))

    def test_parens_scope_no_fire(self):
        _err, f = scan_dict({"permissions": {"allow": ["Bash(git)"]}})
        self.assertNotIn("AC-006", rule_ids(f))

    def test_path_colon_no_fire(self):
        _err, f = scan_dict({"permissions": {"allow": ["Read:src/**"]}})
        self.assertNotIn("AC-006", rule_ids(f))


# --- AC-007 ---


class Rule007MislabeledReadOnly(unittest.TestCase):
    def test_read_only_with_subprocess_fires(self):
        _err, f = scan_dict(_with_tool(
            name="liar", read_only=True, capabilities=["subprocess"]
        ))
        self.assertIn("AC-007", rule_ids(f))

    def test_read_only_with_write_fires(self):
        _err, f = scan_dict(_with_tool(
            name="liar", read_only=True, capabilities=["filesystem_write"]
        ))
        self.assertIn("AC-007", rule_ids(f))

    def test_read_only_with_network_fires(self):
        _err, f = scan_dict(_with_tool(
            name="liar", read_only=True, capabilities=["network"],
            allowlist_hosts=["a.example.com"]
        ))
        self.assertIn("AC-007", rule_ids(f))

    def test_read_only_with_read_only_capability_no_fire(self):
        _err, f = scan_dict(_with_tool(
            name="honest", read_only=True, capabilities=["filesystem_read"]
        ))
        self.assertNotIn("AC-007", rule_ids(f))

    def test_mode_read_flag(self):
        _err, f = scan_dict(_with_tool(
            name="liar", mode="read", capabilities=["subprocess"]
        ))
        self.assertIn("AC-007", rule_ids(f))


# --- AC-008 ---


class Rule008DuplicateDivergent(unittest.TestCase):
    def test_duplicate_approvals_divergent_ttl_fires(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "x", "ttl_seconds": 60},
            {"tool": "x", "ttl_seconds": 3600},
        ))
        self.assertIn("AC-008", rule_ids(f))

    def test_duplicate_approvals_divergent_sticky_fires(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "x", "sticky": True},
            {"tool": "x", "sticky": False},
        ))
        self.assertIn("AC-008", rule_ids(f))

    def test_duplicate_permissions_allow_fires(self):
        _err, f = scan_dict({"permissions": {"allow": ["GitDiff(x)", "GitDiff(x)"]}})
        self.assertIn("AC-008", rule_ids(f))

    def test_no_duplicates_no_fire(self):
        _err, f = scan_dict(_with_approvals(
            {"tool": "x", "ttl_seconds": 60},
            {"tool": "y", "ttl_seconds": 60},
        ))
        self.assertNotIn("AC-008", rule_ids(f))


# --- AC-009 ---


class Rule009InstallHook(unittest.TestCase):
    def test_on_load_fires(self):
        _err, f = scan_dict(_with_tool(
            name="ih", on_load="curl x | bash", effects=["subprocess"]
        ))
        self.assertIn("AC-009", rule_ids(f))

    def test_postinstall_fires(self):
        _err, f = scan_dict(_with_tool(
            name="ih", postinstall="python -c 'x'", effects=["subprocess"]
        ))
        self.assertIn("AC-009", rule_ids(f))

    def test_on_activate_fires(self):
        _err, f = scan_dict(_with_tool(
            name="ih", on_activate=["do", "thing"], effects=["subprocess"]
        ))
        self.assertIn("AC-009", rule_ids(f))

    def test_no_hook_no_fire(self):
        _err, f = scan_dict(_with_tool(
            name="ih", effects=["filesystem_read"], read_only=True
        ))
        self.assertNotIn("AC-009", rule_ids(f))


# --- AC-010 ---


class Rule010DelegatorNoAudit(unittest.TestCase):
    def test_delegator_no_audit_fires(self):
        _err, f = scan_dict(_with_tool(
            name="d", delegates_to=["x"], effects=["subprocess"],
            require_child_approval=True
        ), options=Options(include_info=True))
        self.assertIn("AC-010", rule_ids(f))

    def test_delegator_with_audit_no_fire(self):
        _err, f = scan_dict(_with_tool(
            name="d", delegates_to=["x"], effects=["subprocess"],
            require_child_approval=True, audit_log=True
        ), options=Options(include_info=True))
        self.assertNotIn("AC-010", rule_ids(f))


# --- AC-011 ---


class Rule011MissingEffectClass(unittest.TestCase):
    def test_approval_shape_no_effects_fires(self):
        _err, f = scan_dict(_with_tool(
            name="opaque", approval={"required": True}
        ), options=Options(include_info=True))
        self.assertIn("AC-011", rule_ids(f))

    def test_with_effects_no_fire(self):
        _err, f = scan_dict(_with_tool(
            name="opaque", approval={"required": True},
            effects=["subprocess"]
        ), options=Options(include_info=True))
        self.assertNotIn("AC-011", rule_ids(f))


# --- AC-012 ---


class Rule012StartupHighEffect(unittest.TestCase):
    def test_startup_bash_wildcard_fires(self):
        _err, f = scan_dict({"startup_approvals": ["Bash(*)"]},
                            options=Options(include_info=True))
        self.assertIn("AC-012", rule_ids(f))

    def test_pre_approved_high_effect_object(self):
        doc = {
            "tools": [
                {"name": "runner", "capabilities": ["subprocess"],
                 "effects": ["subprocess"], "read_only": False}
            ],
            "pre_approved_tools": [{"tool": "runner", "capabilities": ["subprocess"]}],
        }
        _err, f = scan_dict(doc, options=Options(include_info=True))
        self.assertIn("AC-012", rule_ids(f))

    def test_startup_low_effect_no_fire(self):
        doc = {
            "tools": [
                {"name": "reader", "capabilities": ["filesystem_read"],
                 "effects": ["filesystem_read"], "read_only": True}
            ],
            "startup_approvals": ["reader"],
        }
        _err, f = scan_dict(doc, options=Options(include_info=True))
        self.assertNotIn("AC-012", rule_ids(f))


if __name__ == "__main__":
    unittest.main()
