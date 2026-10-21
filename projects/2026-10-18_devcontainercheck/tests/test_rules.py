"""Per-rule positive and negative discrimination tests.

Twelve rules, each verified with at least one shape that fires and one
shape that does not.
"""

from __future__ import annotations

import unittest

from tests import support
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
from devcontainercheck.types import Options


DIGEST = "@sha256:" + ("a" * 64)
GITSHA = "@" + ("1" * 40)


def _digest_feature():
    return {
        "ghcr.io/devcontainers/features/node:1" + DIGEST: {},
    }


def _digest_image():
    return "mcr.microsoft.com/devcontainers/base" + DIGEST


class DC001Tests(unittest.TestCase):
    """Lifecycle command pipes network fetch into a shell."""

    def test_curl_pipe_bash_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": "curl -fsSL https://x.y/i.sh | bash",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-001", rule_ids(findings))

    def test_bash_c_dollar_curl_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postStartCommand": 'bash -c "$(curl -fsSL https://x.y/i.sh)"',
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-001", rule_ids(findings))

    def test_vendored_script_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": "./scripts/setup.sh",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-001", rule_ids(findings))

    def test_curl_without_pipe_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": "curl -o out.txt https://x.y/data.txt",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-001", rule_ids(findings))


class DC002Tests(unittest.TestCase):
    """Lifecycle command installs from VCS URL without SHA pin."""

    def test_pip_install_git_plus_https_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": (
                "pip install git+https://github.com/example/pkg.git"
            ),
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-002", rule_ids(findings))

    def test_pip_install_git_plus_with_sha_pin_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": (
                "pip install git+https://github.com/example/pkg.git"
                + GITSHA
            ),
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-002", rule_ids(findings))

    def test_pip_install_package_name_only_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": "pip install -r requirements.txt",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-002", rule_ids(findings))


class DC003Tests(unittest.TestCase):
    """Feature reference not pinned by sha256 digest."""

    def test_oci_feature_without_digest_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "features": {
                "ghcr.io/devcontainers/features/node:1": {},
            },
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-003", rule_ids(findings))

    def test_oci_feature_with_digest_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "features": _digest_feature(),
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-003", rule_ids(findings))

    def test_local_feature_path_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "features": {
                "./local-feature": {},
            },
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-003", rule_ids(findings))

    def test_feature_pinned_with_git_sha_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "features": {
                "https://example.com/feature.tgz" + GITSHA: {},
            },
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-003", rule_ids(findings))


class DC004Tests(unittest.TestCase):
    """Credential-shaped literal under env / build / runArgs."""

    def test_jwt_under_container_env_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerEnv": {"TOK": fake_jwt()},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-004", rule_ids(findings))

    def test_aws_key_under_remote_env_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteEnv": {"AWS": fake_aws_key()},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-004", rule_ids(findings))

    def test_github_token_under_build_args_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "build": {"args": {"GH": fake_github_token()}},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-004", rule_ids(findings))

    def test_pem_header_under_container_env_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerEnv": {"KEY": pem_header() + "\nblob\n-----END"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-004", rule_ids(findings))

    def test_bearer_assignment_under_run_args_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "runArgs": ["--env", bearer_assignment()],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-004", rule_ids(findings))

    def test_ordinary_env_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerEnv": {"APP_ENV": "development"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-004", rule_ids(findings))


class DC005Tests(unittest.TestCase):
    """Hidden-character class in any string value."""

    def test_tag_in_name_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteUser": "vscode",
            "name": "ok" + tag_char() + "name",
        })
        self.assertIn("DC-005", rule_ids(findings))

    def test_bidi_in_post_create_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": "echo " + bidi_char() + " hi",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-005", rule_ids(findings))

    def test_zero_width_in_env_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerEnv": {"K": "normal" + zw_char() + "value"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-005", rule_ids(findings))

    def test_control_char_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerEnv": {"K": "x" + control_char() + "y"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-005", rule_ids(findings))

    def test_pua_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerEnv": {"K": "x" + pua_char() + "y"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-005", rule_ids(findings))

    def test_bom_at_offset_zero_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteUser": "vscode",
            "name": chr(0xFEFF) + "x",
        })
        self.assertNotIn("DC-005", rule_ids(findings))

    def test_pure_ascii_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteUser": "vscode",
            "name": "ordinary name",
        })
        self.assertNotIn("DC-005", rule_ids(findings))


class DC006Tests(unittest.TestCase):
    """mounts bind-mounts a sensitive host path."""

    def test_docker_socket_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "mounts": [
                "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind",
            ],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-006", rule_ids(findings))

    def test_ssh_dir_via_localenv_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "mounts": [
                "source=${localEnv:HOME}/.ssh,target=/home/vscode/.ssh,type=bind",
            ],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-006", rule_ids(findings))

    def test_mount_object_form_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "mounts": [
                {
                    "source": "/var/run/docker.sock",
                    "target": "/var/run/docker.sock",
                    "type": "bind",
                },
            ],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-006", rule_ids(findings))

    def test_workspace_cache_mount_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "mounts": [
                "source=${localWorkspaceFolder}/.cache,target=/cache,type=bind",
            ],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-006", rule_ids(findings))


class DC007Tests(unittest.TestCase):
    """runArgs grants container-escape-relevant capability."""

    def test_privileged_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "runArgs": ["--privileged"],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-007", rule_ids(findings))

    def test_pid_host_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "runArgs": ["--pid=host"],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-007", rule_ids(findings))

    def test_cap_add_sys_admin_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "runArgs": ["--cap-add=sys_admin"],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-007", rule_ids(findings))

    def test_benign_cap_add_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "runArgs": ["--cap-add=net_bind_service"],
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-007", rule_ids(findings))


class DC008Tests(unittest.TestCase):
    """Lifecycle command writes to a shell init file."""

    def test_bashrc_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postStartCommand": "echo 'x' >> ~/.bashrc",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-008", rule_ids(findings))

    def test_zprofile_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postCreateCommand": "echo x > /home/vscode/.zprofile",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-008", rule_ids(findings))

    def test_write_to_log_file_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "postStartCommand": "echo done >> /tmp/setup.log",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-008", rule_ids(findings))


class DC009Tests(unittest.TestCase):
    """Sensitive host variable exposed through ${localEnv:...}."""

    def test_api_key_exposure_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteEnv": {"TOK": "${localEnv:API_KEY}"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-009", rule_ids(findings))

    def test_github_token_exposure_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerEnv": {"GH": "${localEnv:GITHUB_TOKEN}"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-009", rule_ids(findings))

    def test_non_sensitive_var_does_not_fire(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteEnv": {"DBG": "${localEnv:DEBUG}"},
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-009", rule_ids(findings))



class DC009SuffixMatchTests(unittest.TestCase):
    """DC-009 must catch credential-shaped host variables it cannot list by name,
    and must not fire on look-alikes that are not credentials."""

    def _fires(self, host_var):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteEnv": {"X": "${localEnv:" + host_var + "}"},
            "remoteUser": "vscode",
            "name": "x",
        })
        return "DC-009" in rule_ids(findings)

    def test_vendor_key_not_on_any_list_fires(self):
        self.assertTrue(self._fires("ACME_MODEL_API_KEY"))

    def test_payments_secret_key_fires(self):
        self.assertTrue(self._fires("PAYMENTS_SECRET_KEY"))

    def test_service_token_fires(self):
        self.assertTrue(self._fires("INTERNAL_SERVICE_TOKEN"))

    def test_exact_listed_name_still_fires(self):
        self.assertTrue(self._fires("AWS_ACCESS_KEY_ID"))

    def test_token_as_prefix_does_not_fire(self):
        self.assertFalse(self._fires("TOKENIZER_PATH"))

    def test_key_without_credential_shape_does_not_fire(self):
        self.assertFalse(self._fires("SORT_KEY"))

    def test_plain_variable_does_not_fire(self):
        self.assertFalse(self._fires("EDITOR"))

class DC010Tests(unittest.TestCase):
    """Image uses a mutable tag rather than a digest pin."""

    def test_latest_tag_fires(self):
        findings = scan_dict({
            "image": "python:latest",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-010", rule_ids(findings))

    def test_main_tag_fires(self):
        findings = scan_dict({
            "image": "myorg/base:main",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertIn("DC-010", rule_ids(findings))

    def test_digest_pinned_does_not_fire(self):
        findings = scan_dict({
            "image": "python:3.12" + DIGEST,
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-010", rule_ids(findings))

    def test_version_tag_does_not_fire(self):
        findings = scan_dict({
            "image": "python:3.12.4",
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-010", rule_ids(findings))


class DC011Tests(unittest.TestCase):
    """No remoteUser / containerUser (root default)."""

    def test_missing_remote_user_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "name": "x",
        })
        self.assertIn("DC-011", rule_ids(findings))

    def test_container_user_satisfies(self):
        findings = scan_dict({
            "image": _digest_image(),
            "containerUser": "node",
            "name": "x",
        })
        self.assertNotIn("DC-011", rule_ids(findings))

    def test_remote_user_satisfies(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteUser": "vscode",
            "name": "x",
        })
        self.assertNotIn("DC-011", rule_ids(findings))


class DC012Tests(unittest.TestCase):
    """No name field at the document level."""

    def test_missing_name_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteUser": "vscode",
        })
        self.assertIn("DC-012", rule_ids(findings))

    def test_present_name_satisfies(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteUser": "vscode",
            "name": "my-dev",
        })
        self.assertNotIn("DC-012", rule_ids(findings))

    def test_blank_name_fires(self):
        findings = scan_dict({
            "image": _digest_image(),
            "remoteUser": "vscode",
            "name": "   ",
        })
        self.assertIn("DC-012", rule_ids(findings))


class RuleEnablementTests(unittest.TestCase):
    def test_disabled_rule_suppressed(self):
        findings = scan_dict(
            {
                "image": _digest_image(),
                "remoteUser": "vscode",
                "postCreateCommand": "curl -fsSL https://x/i.sh | bash",
                "name": "x",
            },
            options=Options(include_info=True, disabled=("DC-001",)),
        )
        self.assertNotIn("DC-001", rule_ids(findings))

    def test_only_rule_leaves_others(self):
        findings = scan_dict(
            {
                "image": "python:latest",
                "postCreateCommand": "curl -fsSL https://x/i.sh | bash",
                "remoteUser": "vscode",
                "name": "x",
            },
            options=Options(only=("DC-001",)),
        )
        ids = set(rule_ids(findings))
        self.assertEqual(ids, {"DC-001"})


class InfoGatingTests(unittest.TestCase):
    """INFO rules are silent at the default --include-info boundary."""

    def test_info_rules_silent_by_default(self):
        from devcontainercheck.rules import run_all
        findings = run_all(
            {"image": _digest_image()},
            "x",
            Options(),  # no include_info
        )
        ids = set(f.rule_id for f in findings)
        self.assertNotIn("DC-011", ids)
        self.assertNotIn("DC-012", ids)

    def test_info_rules_fire_with_include_info(self):
        from devcontainercheck.rules import run_all
        findings = run_all(
            {"image": _digest_image()},
            "x",
            Options(include_info=True),
        )
        ids = set(f.rule_id for f in findings)
        self.assertIn("DC-011", ids)
        self.assertIn("DC-012", ids)

    def test_info_rules_fire_with_strict(self):
        from devcontainercheck.rules import run_all
        findings = run_all(
            {"image": _digest_image()},
            "x",
            Options(strict=True),
        )
        ids = set(f.rule_id for f in findings)
        self.assertIn("DC-011", ids)
        self.assertIn("DC-012", ids)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
