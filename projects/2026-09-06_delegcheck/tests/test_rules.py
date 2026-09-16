import json
import unittest

from delegcheck.rules import ALL_RULES, run_rules
from delegcheck.types import Severity


def _run(obj):
    text = json.dumps(obj, indent=2)
    return run_rules(obj, text, "test.json")


def _run_only(obj, rule_id):
    text = json.dumps(obj, indent=2)
    disabled = frozenset(r.id for r in ALL_RULES if r.id != rule_id)
    return run_rules(obj, text, "test.json", disabled=disabled)


class TestRegistry(unittest.TestCase):

    def test_ten_rules(self):
        self.assertEqual(len(ALL_RULES), 10)

    def test_ids_unique(self):
        ids = [r.id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_canonical(self):
        for i, r in enumerate(ALL_RULES, start=1):
            self.assertEqual(r.id, "DEL-" + str(i).zfill(3))

    def test_descriptions_non_empty(self):
        for r in ALL_RULES:
            self.assertTrue(r.description.strip())

    def test_severities_valid(self):
        for r in ALL_RULES:
            self.assertIn(r.severity, (Severity.HIGH, Severity.MEDIUM, Severity.INFO))

    def test_severity_split(self):
        high = sum(1 for r in ALL_RULES if r.severity == Severity.HIGH)
        medium = sum(1 for r in ALL_RULES if r.severity == Severity.MEDIUM)
        info = sum(1 for r in ALL_RULES if r.severity == Severity.INFO)
        self.assertEqual((high, medium, info), (5, 4, 1))

    def test_check_fns_callable(self):
        for r in ALL_RULES:
            self.assertTrue(callable(r.check_fn))


class TestDEL001UnboundedScope(unittest.TestCase):

    def test_star_scope_fires(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value_ref": "vault://t", "scope": "*"}]}
        f = _run_only(obj, "DEL-001")
        self.assertEqual(len(f), 1)

    def test_all_scope_fires(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value_ref": "vault://t", "scope": "all"}]}
        f = _run_only(obj, "DEL-001")
        self.assertEqual(len(f), 1)

    def test_missing_scope_fires(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value_ref": "vault://t"}]}
        f = _run_only(obj, "DEL-001")
        self.assertEqual(len(f), 1)

    def test_empty_scope_fires(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value_ref": "vault://t", "scope": "   "}]}
        f = _run_only(obj, "DEL-001")
        self.assertEqual(len(f), 1)

    def test_list_with_star_fires(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value_ref": "vault://t", "scope": ["read:issues", "*"]}]}
        f = _run_only(obj, "DEL-001")
        self.assertEqual(len(f), 1)

    def test_narrow_scope_clean(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value_ref": "vault://t", "scope": "read:issues:public"}]}
        f = _run_only(obj, "DEL-001")
        self.assertEqual(f, [])

    def test_non_bearer_ignored(self):
        obj = {"credentials": [{"name": "cert", "type": "mtls", "scope": "*"}]}
        f = _run_only(obj, "DEL-001")
        self.assertEqual(f, [])


class TestDEL002NoPrincipal(unittest.TestCase):

    def test_missing_principal_fires(self):
        obj = {"tools": [{"name": "shell"}]}
        f = _run_only(obj, "DEL-002")
        self.assertEqual(len(f), 1)

    def test_principal_ok(self):
        obj = {"tools": [{"name": "shell", "principal": "worker-1"}]}
        f = _run_only(obj, "DEL-002")
        self.assertEqual(f, [])

    def test_owner_ok(self):
        obj = {"tools": [{"name": "shell", "owner": "worker-1"}]}
        f = _run_only(obj, "DEL-002")
        self.assertEqual(f, [])

    def test_identity_ok(self):
        obj = {"tools": [{"name": "shell", "identity": "worker-1"}]}
        f = _run_only(obj, "DEL-002")
        self.assertEqual(f, [])

    def test_sub_ok(self):
        obj = {"tools": [{"name": "shell", "sub": "worker-1"}]}
        f = _run_only(obj, "DEL-002")
        self.assertEqual(f, [])

    def test_multiple_tools_partial_fire(self):
        obj = {"tools": [
            {"name": "a", "principal": "w"},
            {"name": "b"},
        ]}
        f = _run_only(obj, "DEL-002")
        self.assertEqual(len(f), 1)


class TestDEL003AuthInModel(unittest.TestCase):

    def test_llm_mode_fires(self):
        obj = {"authorization": {"mode": "llm"}}
        f = _run_only(obj, "DEL-003")
        self.assertEqual(len(f), 1)

    def test_model_mode_fires(self):
        obj = {"authorization": {"mode": "model"}}
        f = _run_only(obj, "DEL-003")
        self.assertEqual(len(f), 1)

    def test_agent_decides_fires(self):
        obj = {"authorization": {"gate": "agent-decides"}}
        f = _run_only(obj, "DEL-003")
        self.assertEqual(len(f), 1)

    def test_in_context_fires(self):
        obj = {"authorization": {"mode": "in-context"}}
        f = _run_only(obj, "DEL-003")
        self.assertEqual(len(f), 1)

    def test_external_clean(self):
        obj = {"authorization": {"mode": "external", "gate": "policy-engine"}}
        f = _run_only(obj, "DEL-003")
        self.assertEqual(f, [])

    def test_no_authorization_clean(self):
        f = _run_only({}, "DEL-003")
        self.assertEqual(f, [])


class TestDEL004ParentCredReuse(unittest.TestCase):

    def _base(self, extra_del=None):
        d = {"from": "orchestrator", "to": "worker", "credential_ref": "root_token"}
        if extra_del:
            d.update(extra_del)
        return {
            "credentials": [{"name": "root_token", "type": "bearer", "value_ref": "vault://root", "scope": "read:issues", "expires_at": "2026-10-01"}],
            "delegations": [d],
        }

    def test_verbatim_reuse_fires(self):
        f = _run_only(self._base(), "DEL-004")
        self.assertEqual(len(f), 1)

    def test_narrowed_scope_clean(self):
        f = _run_only(self._base({"narrowed_scope": "read:issues:public"}), "DEL-004")
        self.assertEqual(f, [])

    def test_sub_scope_clean(self):
        f = _run_only(self._base({"sub_scope": "read:issues:public"}), "DEL-004")
        self.assertEqual(f, [])

    def test_constrained_scope_clean(self):
        f = _run_only(self._base({"constrained_scope": "read:issues:public"}), "DEL-004")
        self.assertEqual(f, [])

    def test_unknown_cred_ref_clean(self):
        obj = self._base()
        obj["delegations"][0]["credential_ref"] = "does_not_exist"
        f = _run_only(obj, "DEL-004")
        self.assertEqual(f, [])


class TestDEL005RecursiveNoCap(unittest.TestCase):

    def test_missing_depth_cap_fires(self):
        obj = {"delegations": [{"from": "a", "to": "b"}]}
        f = _run_only(obj, "DEL-005")
        self.assertEqual(len(f), 1)

    def test_max_depth_clean(self):
        obj = {"delegations": [{"from": "a", "to": "b", "max_depth": 1}]}
        f = _run_only(obj, "DEL-005")
        self.assertEqual(f, [])

    def test_hop_limit_clean(self):
        obj = {"delegations": [{"from": "a", "to": "b", "hop_limit": 2}]}
        f = _run_only(obj, "DEL-005")
        self.assertEqual(f, [])

    def test_depth_limit_clean(self):
        obj = {"delegations": [{"from": "a", "to": "b", "depth_limit": 3}]}
        f = _run_only(obj, "DEL-005")
        self.assertEqual(f, [])

    def test_no_delegations_clean(self):
        f = _run_only({}, "DEL-005")
        self.assertEqual(f, [])


class TestDEL006WildcardAgent(unittest.TestCase):

    def test_star_string_fires(self):
        obj = {"tools": [{"name": "t", "principal": "o", "permitted_agents": "*"}]}
        f = _run_only(obj, "DEL-006")
        self.assertEqual(len(f), 1)

    def test_star_in_list_fires(self):
        obj = {"tools": [{"name": "t", "principal": "o", "permitted_agents": ["a", "*"]}]}
        f = _run_only(obj, "DEL-006")
        self.assertEqual(len(f), 1)

    def test_all_string_fires(self):
        obj = {"tools": [{"name": "t", "principal": "o", "permitted_agents": "all"}]}
        f = _run_only(obj, "DEL-006")
        self.assertEqual(len(f), 1)

    def test_callers_field_fires(self):
        obj = {"tools": [{"name": "t", "principal": "o", "callers": "*"}]}
        f = _run_only(obj, "DEL-006")
        self.assertEqual(len(f), 1)

    def test_specific_list_clean(self):
        obj = {"tools": [{"name": "t", "principal": "o", "permitted_agents": ["a", "b"]}]}
        f = _run_only(obj, "DEL-006")
        self.assertEqual(f, [])


class TestDEL007NoExpiry(unittest.TestCase):

    def _cred(self, **extra):
        base = {"name": "t", "type": "bearer", "value_ref": "vault://t", "scope": "read:issues"}
        base.update(extra)
        return {"credentials": [base]}

    def test_missing_expiry_fires(self):
        f = _run_only(self._cred(), "DEL-007")
        self.assertEqual(len(f), 1)

    def test_expires_at_clean(self):
        f = _run_only(self._cred(expires_at="2026-10-01"), "DEL-007")
        self.assertEqual(f, [])

    def test_ttl_seconds_clean(self):
        f = _run_only(self._cred(ttl_seconds=300), "DEL-007")
        self.assertEqual(f, [])

    def test_not_after_clean(self):
        f = _run_only(self._cred(not_after="2026-10-01"), "DEL-007")
        self.assertEqual(f, [])

    def test_non_bearer_clean(self):
        obj = {"credentials": [{"name": "cert", "type": "mtls"}]}
        f = _run_only(obj, "DEL-007")
        self.assertEqual(f, [])


class TestDEL008BoundaryMismatch(unittest.TestCase):

    def test_internal_across_principals_fires(self):
        obj = {"delegations": [{"from": "a", "to": "b", "trust_boundary": "internal"}]}
        f = _run_only(obj, "DEL-008")
        self.assertEqual(len(f), 1)

    def test_same_principal_clean(self):
        obj = {"delegations": [{"from": "a", "to": "a", "trust_boundary": "internal"}]}
        f = _run_only(obj, "DEL-008")
        self.assertEqual(f, [])

    def test_external_boundary_clean(self):
        obj = {"delegations": [{"from": "a", "to": "b", "trust_boundary": "external"}]}
        f = _run_only(obj, "DEL-008")
        self.assertEqual(f, [])

    def test_no_boundary_clean(self):
        obj = {"delegations": [{"from": "a", "to": "b"}]}
        f = _run_only(obj, "DEL-008")
        self.assertEqual(f, [])

    def test_boundary_alias_field(self):
        obj = {"delegations": [{"from": "a", "to": "b", "boundary": "same"}]}
        f = _run_only(obj, "DEL-008")
        self.assertEqual(len(f), 1)


class TestDEL009Cycle(unittest.TestCase):

    def test_triangle_cycle_fires(self):
        obj = {"delegations": [
            {"from": "a", "to": "b"},
            {"from": "b", "to": "c"},
            {"from": "c", "to": "a"},
        ]}
        f = _run_only(obj, "DEL-009")
        self.assertGreaterEqual(len(f), 1)

    def test_self_loop_fires(self):
        obj = {"delegations": [{"from": "a", "to": "a"}]}
        f = _run_only(obj, "DEL-009")
        self.assertGreaterEqual(len(f), 1)

    def test_two_node_cycle_fires(self):
        obj = {"delegations": [
            {"from": "a", "to": "b"},
            {"from": "b", "to": "a"},
        ]}
        f = _run_only(obj, "DEL-009")
        self.assertGreaterEqual(len(f), 1)

    def test_linear_chain_clean(self):
        obj = {"delegations": [
            {"from": "a", "to": "b"},
            {"from": "b", "to": "c"},
            {"from": "c", "to": "d"},
        ]}
        f = _run_only(obj, "DEL-009")
        self.assertEqual(f, [])

    def test_empty_clean(self):
        f = _run_only({"delegations": []}, "DEL-009")
        self.assertEqual(f, [])


class TestDEL010BearerLiteral(unittest.TestCase):

    def _long_token(self):
        parts = ("a1B2c3D4e5F6g7H8", "i9J0k1L2m3N4o5P6", "Q7r8S9t0U1v2W3x4")
        return "".join(parts)

    def test_long_bearer_literal_fires(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value": self._long_token()}]}
        f = _run_only(obj, "DEL-010")
        self.assertEqual(len(f), 1)

    def test_short_literal_clean(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value": "abcdef"}]}
        f = _run_only(obj, "DEL-010")
        self.assertEqual(f, [])

    def test_vault_ref_clean(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value_ref": "vault://xyz-long-name-that-exceeds-32-chars-plenty"}]}
        f = _run_only(obj, "DEL-010")
        self.assertEqual(f, [])

    def test_low_entropy_clean(self):
        obj = {"credentials": [{"name": "t", "type": "bearer", "value": "a" * 50}]}
        f = _run_only(obj, "DEL-010")
        self.assertEqual(f, [])

    def test_non_bearer_clean(self):
        obj = {"credentials": [{"name": "cert", "type": "mtls", "value": self._long_token()}]}
        f = _run_only(obj, "DEL-010")
        self.assertEqual(f, [])


class TestOrdinaryContentFiresNothing(unittest.TestCase):

    def test_empty_dict_no_findings(self):
        self.assertEqual(_run({}), [])

    def test_healthy_config_no_findings(self):
        obj = {
            "agent": "w",
            "credentials": [{
                "name": "t", "type": "bearer", "value_ref": "vault://t",
                "scope": "read:issues", "expires_at": "2026-10-01",
            }],
            "tools": [{"name": "list", "principal": "w", "permitted_agents": ["w"]}],
            "delegations": [{
                "from": "orch", "to": "w", "credential_ref": "t",
                "narrowed_scope": "read:issues:public", "max_depth": 1,
                "trust_boundary": "external",
            }],
            "authorization": {"mode": "external"},
        }
        self.assertEqual(_run(obj), [])


if __name__ == "__main__":
    unittest.main()
