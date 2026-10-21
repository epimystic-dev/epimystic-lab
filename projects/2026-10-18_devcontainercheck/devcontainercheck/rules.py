"""Rule registry for devcontainercheck.

Twelve shape defects on the ``devcontainer.json`` surface. Rule IDs
use the ``DC-`` prefix (Dev Container); the lab-wide shared surface
exposes this list as ``ALL_RULES``.

The attack family is grounded in:

- The Microsoft dev containers specification
  (https://containers.dev/implementors/json_reference/), which names
  ``initializeCommand``, ``onCreateCommand``, ``updateContentCommand``,
  ``postCreateCommand``, ``postStartCommand``, and ``postAttachCommand``
  as the lifecycle slots that execute on container create / attach.
- VS Code Workspace Trust documentation, which warns that opening an
  untrusted folder with a ``devcontainer.json`` can execute those
  lifecycle commands when the folder is marked trusted.
- The October 2026 ``GhostAction`` supply-chain campaign
  (`thehackernews.com/2026/10 credential-stealing-github-actions`,
  `blog.gitguardian.com ghostaction-github-actions-supply-chain-attack-returns`,
  2026-10-07 to 2026-10-09): credential-stealing workflows and
  install-time commands planted through tag-pinned (not SHA-pinned)
  dependencies escalated as a dominant 2026 attack vector against CI
  / dev environments.
- The ``containers.dev/features`` registry model, which allows a
  ``features`` block to reference an OCI image, a Git URL, or an HTTP
  tarball; a mutable tag or an arbitrary URL is the devcontainer-side
  equivalent of the GitHub Actions ``uses: owner/repo@v1`` footgun.

The rules are shape-only: a devcontainer.json is a developer-authored
artifact that lives on disk and is read by consumers; shape defects at
that layer are detectable statically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .parse import coerce_command_strings
from .types import Finding, Options, Severity


Check = Callable[[Any, str, Options], List[Finding]]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    description: str
    check: Check


# ---------------------------------------------------------------------------
# Hidden-character classifier (shared with sibling linters).
# ---------------------------------------------------------------------------

TAG_RANGE = (0xE0000, 0xE007F)
BIDI_CODEPOINTS = frozenset(
    [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
)
ZERO_WIDTH_CODEPOINTS = frozenset([0x200B, 0x200C, 0x200D, 0x2060])
BOM_CODEPOINT = 0xFEFF
PUA_RANGES: Tuple[Tuple[int, int], ...] = (
    (0xE000, 0xF8FF),
    (0xF0000, 0xFFFFD),
    (0x100000, 0x10FFFD),
)


def _is_control(cp: int) -> bool:
    if cp in (0x09, 0x0A, 0x0D):
        return False
    if 0x00 <= cp <= 0x1F:
        return True
    if 0x7F <= cp <= 0x9F:
        return True
    return False


def _in_pua(cp: int) -> bool:
    if TAG_RANGE[0] <= cp <= TAG_RANGE[1]:
        return False
    for lo, hi in PUA_RANGES:
        if lo <= cp <= hi:
            return True
    return False


def _classify_hidden(cp: int, idx: int) -> Optional[str]:
    if TAG_RANGE[0] <= cp <= TAG_RANGE[1]:
        return "TAG block"
    if cp in BIDI_CODEPOINTS:
        return "bidi override"
    if cp in ZERO_WIDTH_CODEPOINTS:
        return "zero-width"
    if cp == BOM_CODEPOINT and idx != 0:
        return "BOM"
    if _is_control(cp):
        return "control"
    if _in_pua(cp):
        return "private-use"
    return None


def _walk_strings(obj: Any, pointer: str = ""):
    """Yield (pointer, string) for every string value reached from obj."""
    if isinstance(obj, str):
        yield pointer or "<root>", obj
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _walk_strings(item, pointer + "[" + str(i) + "]")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            sub = pointer + "." + str(k) if pointer else str(k)
            yield from _walk_strings(v, sub)


# ---------------------------------------------------------------------------
# Lifecycle-command helpers (DC-001, DC-002, DC-008).
# ---------------------------------------------------------------------------

LIFECYCLE_KEYS = (
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
)


# Pipe a network fetch into a shell. "curl ... | sh", "wget -q -O- ... | bash".
# The pattern is deliberately broad: a pipe to any shell interpreter after a
# network-fetching tool is the fault class.
_FETCH_AND_EXECUTE = re.compile(
    r"\b(curl|wget|fetch|iwr|invoke-webrequest)\b[^\n;|]*?\|\s*"
    r"(sh|bash|zsh|dash|ash|ksh|pwsh|powershell|python|python3|node|ruby|perl)\b",
    re.IGNORECASE,
)

# A direct exec of a remote script: `bash -c "$(curl ...)"` or
# `sh <(curl ...)`.
_EXEC_REMOTE = re.compile(
    r"\b(bash|sh|zsh|dash|ksh|pwsh|powershell)\b\s+-c\s+[\"']\$\(\s*(curl|wget|iwr)\b",
    re.IGNORECASE,
)
_PROCESS_SUB_REMOTE = re.compile(
    r"\b(bash|sh|zsh|dash|ksh)\b\s+<\(\s*(curl|wget)\b",
    re.IGNORECASE,
)

# A git clone / pip install git+ / cargo install --git from a URL (not
# pinned by @SHA) is a tag-floating supply-chain source.
_UNPINNED_VCS = re.compile(
    r"\b(?:pip\s+install\s+|pip3\s+install\s+|git\s+clone\s+)"
    r"(?:git\+)?https?://[^\s'\"]+",
    re.IGNORECASE,
)

# Writes to shell init files.
_SHELL_INIT = re.compile(
    r"(?:>>|>)\s*[\"']?(?:[~./][\w./\\\-]*)?"
    r"\.(?:bashrc|zshrc|bash_profile|zprofile|profile|zshenv|bash_login|xonshrc|cshrc|tcshrc)"
    r"\b",
    re.IGNORECASE,
)


def _lifecycle_entries(doc: dict):
    """Yield (pointer, command_string) for every lifecycle command slot."""
    if not isinstance(doc, dict):
        return
    for key in LIFECYCLE_KEYS:
        if key not in doc:
            continue
        for suffix, cmd in coerce_command_strings(doc[key]):
            yield "." + key + suffix, cmd


def _check_fetch_and_execute(doc, path, options):
    out: List[Finding] = []
    for pointer, cmd in _lifecycle_entries(doc):
        if _FETCH_AND_EXECUTE.search(cmd) or _EXEC_REMOTE.search(cmd) \
                or _PROCESS_SUB_REMOTE.search(cmd):
            out.append(Finding(
                rule_id="DC-001",
                severity=Severity.HIGH,
                message=(
                    "lifecycle command pipes a network fetch into a "
                    "shell interpreter"
                ),
                pointer=pointer,
                path=path,
                hint=(
                    "A curl / wget / Invoke-WebRequest piped into a "
                    "shell runs whatever bytes the server returns on "
                    "every container create or attach; pin the install "
                    "to a vendored script committed to the repo, or to "
                    "a package manager with signature verification"
                ),
            ))
    return out


def _check_unpinned_install(doc, path, options):
    out: List[Finding] = []
    for pointer, cmd in _lifecycle_entries(doc):
        for m in _UNPINNED_VCS.finditer(cmd):
            url = m.group(0)
            # If the URL carries an explicit @<40-hex> SHA pin, it is
            # not an unpinned install.
            if re.search(r"@[0-9a-f]{40}\b", url):
                continue
            out.append(Finding(
                rule_id="DC-002",
                severity=Severity.HIGH,
                message=(
                    "lifecycle command installs from a VCS URL without "
                    "a commit-SHA pin (" + url + ")"
                ),
                pointer=pointer,
                path=path,
                hint=(
                    "A tag or branch reference is mutable: the published "
                    "artifact on the next container create can differ "
                    "from the one reviewed. Replace the URL with a "
                    "@<40-hex-SHA> pin or use a package-manager "
                    "coordinate with a lockfile"
                ),
            ))
    return out


def _check_shell_init_write(doc, path, options):
    out: List[Finding] = []
    for pointer, cmd in _lifecycle_entries(doc):
        if _SHELL_INIT.search(cmd):
            out.append(Finding(
                rule_id="DC-008",
                severity=Severity.MEDIUM,
                message=(
                    "lifecycle command writes to a shell init file "
                    "(persistent dotfile mutation)"
                ),
                pointer=pointer,
                path=path,
                hint=(
                    "A persistent dotfile write hides the mutation from "
                    "a reader who inspects only devcontainer.json; keep "
                    "shell-init changes in a committed, reviewable file"
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# Features and image rules (DC-003, DC-010).
# ---------------------------------------------------------------------------

# A features entry can be an OCI reference, a Git reference, or an HTTP
# tarball URL. We flag any reference missing a SHA256 digest pin
# (``@sha256:<64hex>``) or an explicit git-SHA fragment.
_SHA256_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")
_FORTY_HEX = re.compile(r"@[0-9a-f]{40}\b")
_OCI_FEATURE = re.compile(
    r"^(?:ghcr\.io|docker\.io|quay\.io|mcr\.microsoft\.com|registry\.k8s\.io|"
    r"public\.ecr\.aws)/",
    re.IGNORECASE,
)


def _check_feature_pinning(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    features = doc.get("features")
    if not isinstance(features, dict):
        return out
    for name, _value in features.items():
        if not isinstance(name, str):
            continue
        pointer = ".features." + name
        # Local-path features (``./local-feature`` or
        # ``file://...``) are not a mutable-tag surface and are
        # treated as adequately pinned.
        if name.startswith(("./", "../", "file:")) or name.startswith("/"):
            continue
        if _SHA256_DIGEST.search(name):
            continue
        if _FORTY_HEX.search(name):
            continue
        if _OCI_FEATURE.search(name) or name.startswith("oci://"):
            out.append(Finding(
                rule_id="DC-003",
                severity=Severity.HIGH,
                message=(
                    "feature reference '" + name + "' is not pinned by "
                    "sha256 digest (mutable tag)"
                ),
                pointer=pointer,
                path=path,
                hint=(
                    "OCI feature references should carry an "
                    "@sha256:<digest> suffix; a tag (:1, :latest) can "
                    "silently move to new bytes between container "
                    "builds"
                ),
            ))
            continue
        if name.startswith(("http://", "https://", "git+", "ghcr.io/")):
            out.append(Finding(
                rule_id="DC-003",
                severity=Severity.HIGH,
                message=(
                    "feature reference '" + name + "' is a raw URL "
                    "without a commit-SHA pin"
                ),
                pointer=pointer,
                path=path,
                hint=(
                    "Raw HTTP(S) / git URLs are mutable; prefer an "
                    "OCI reference pinned to @sha256:<digest>, or "
                    "pin the URL to @<40-hex-git-SHA>"
                ),
            ))


    return out


_LATEST_TAG = re.compile(r":(latest|main|master|dev|develop|edge|nightly)$")


def _check_image_pinning(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    image = doc.get("image")
    if not isinstance(image, str):
        return out
    if _SHA256_DIGEST.search(image):
        return out
    if _LATEST_TAG.search(image):
        out.append(Finding(
            rule_id="DC-010",
            severity=Severity.MEDIUM,
            message=(
                "image '" + image + "' uses a mutable tag; pin to "
                "@sha256:<digest> for reproducibility"
            ),
            pointer=".image",
            path=path,
            hint=(
                "A mutable tag (latest, main, dev, nightly) resolves to "
                "whatever bytes the registry serves at pull time; a "
                "digest-pinned image is reproducible and signature-"
                "verifiable"
            ),
        ))
    return out


# ---------------------------------------------------------------------------
# Credential-shape rule (DC-004).
# ---------------------------------------------------------------------------

_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_AWS_RE = re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16}\b")
_GITHUB_RE = re.compile(r"\b(ghp|ghs|gho|ghu|ghr)_[A-Za-z0-9]{30,}\b")
_PEM_RE = re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----")
_BEARER_RE = re.compile(
    r"\b(?:bearer|api[_-]?key|secret|password|token)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9_\-\.]{20,})",
    re.IGNORECASE,
)


_CRED_RULES = (
    (_JWT_RE, "JWT"),
    (_AWS_RE, "AWS-style access key"),
    (_GITHUB_RE, "GitHub token"),
    (_PEM_RE, "PEM private-key header"),
    (_BEARER_RE, "bearer/api-key assignment"),
)


def _credential_shape(text: str) -> Optional[str]:
    for rx, label in _CRED_RULES:
        if rx.search(text):
            return label
    return None


# Keys where a credential-shaped literal would be inlined.
_CRED_SCOPE_KEYS = (
    "containerEnv", "remoteEnv", "build", "runArgs",
    "runArguments",
)


def _check_credential_literal(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    for scope_key in _CRED_SCOPE_KEYS:
        value = doc.get(scope_key)
        if value is None:
            continue
        for pointer, text in _walk_strings(value, scope_key):
            label = _credential_shape(text)
            if label is None:
                continue
            out.append(Finding(
                rule_id="DC-004",
                severity=Severity.HIGH,
                message=(
                    "credential-shaped literal (" + label + ") inlined "
                    "under " + scope_key
                ),
                pointer="." + pointer,
                path=path,
                hint=(
                    "A credential committed to devcontainer.json is "
                    "shipped to every clone of the repository; move "
                    "it to a secret store the container reads at run "
                    "time (e.g. a CODESPACES secret, a direnv-managed "
                    "environment variable, or a mounted secret file)"
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# Hidden-character rule (DC-005).
# ---------------------------------------------------------------------------

def _check_hidden_characters(doc, path, options):
    out: List[Finding] = []
    for pointer, text in _walk_strings(doc, ""):
        for idx, ch in enumerate(text):
            cp = ord(ch)
            label = _classify_hidden(cp, idx)
            if label is None:
                continue
            out.append(Finding(
                rule_id="DC-005",
                severity=Severity.HIGH,
                message=(
                    "string value contains " + label + " character "
                    "U+%04X at offset " % cp + str(idx)
                ),
                pointer="." + pointer,
                path=path,
                hint=(
                    "Hidden-character classes (Plane 14 TAG, bidi "
                    "overrides, zero-width, control, PUA) are invisible "
                    "to a human reviewer but reach the shell / tokenizer "
                    "when the string is executed or displayed; strip "
                    "them or reject the value"
                ),
            ))
            break
    return out


# ---------------------------------------------------------------------------
# Mounts (DC-006).
# ---------------------------------------------------------------------------

_MOUNT_SOURCE_RE = re.compile(r"source=([^,]+)")


def _mount_source(entry: Any) -> Optional[str]:
    """Extract the source= component from a mounts entry (string or
    object form).
    """
    if isinstance(entry, str):
        m = _MOUNT_SOURCE_RE.search(entry)
        if m:
            return m.group(1).strip().strip('"').strip("'")
        return None
    if isinstance(entry, dict):
        v = entry.get("source")
        if isinstance(v, str):
            return v
    return None


def _normalise_mount_source(src: str) -> str:
    """Lowercase + strip ``${localEnv:...}`` wrapping so the comparison
    sees the final-path shape. ``${localEnv:HOME}/.ssh`` becomes
    ``$home/.ssh``; a sibling check on the sensitive-path tail then
    fires.
    """
    s = src.strip().strip('"').strip("'")
    s = re.sub(r"\$\{localEnv:([^}]+)\}", r"$\1", s, flags=re.IGNORECASE)
    s = re.sub(r"\$\{localWorkspaceFolder\}", "$ws", s, flags=re.IGNORECASE)
    return s.lower().replace("\\", "/")


def _check_mounts(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    mounts = doc.get("mounts")
    if mounts is None:
        return out
    if not isinstance(mounts, list):
        mounts = [mounts]
    for i, entry in enumerate(mounts):
        src = _mount_source(entry)
        if src is None:
            continue
        norm = _normalise_mount_source(src)
        for sensitive in options.sensitive_host_paths:
            needle = sensitive.lower().replace("\\", "/")
            if norm == needle or norm.endswith("/" + needle) \
                    or norm.endswith(needle):
                out.append(Finding(
                    rule_id="DC-006",
                    severity=Severity.MEDIUM,
                    message=(
                        "mounts[" + str(i) + "] bind-mounts sensitive "
                        "host path '" + src + "'"
                    ),
                    pointer=".mounts[" + str(i) + "]",
                    path=path,
                    hint=(
                        "A host-path bind-mount is a privilege boundary "
                        "crossing; the dev container (and any lifecycle "
                        "command it runs) can read / write the host "
                        "credential or socket. Prefer a vendored copy "
                        "or an explicit, scoped secret mount"
                    ),
                ))
                break
    return out


# ---------------------------------------------------------------------------
# runArgs privileged flags (DC-007).
# ---------------------------------------------------------------------------

_PRIV_FLAGS = (
    "--privileged",
    "--security-opt=seccomp=unconfined",
    "--security-opt=apparmor=unconfined",
    "--cap-add=sys_admin",
    "--cap-add=all",
    "--pid=host",
    "--net=host",
    "--network=host",
    "--ipc=host",
    "--userns=host",
)


def _check_privileged_runargs(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    run_args = doc.get("runArgs")
    if not isinstance(run_args, list):
        return out
    for i, arg in enumerate(run_args):
        if not isinstance(arg, str):
            continue
        low = arg.lower().replace(" ", "")
        for flag in _PRIV_FLAGS:
            if low == flag.lower() or low.startswith(flag.lower() + "="):
                out.append(Finding(
                    rule_id="DC-007",
                    severity=Severity.MEDIUM,
                    message=(
                        "runArgs[" + str(i) + "] = '" + arg + "' grants "
                        "a container-escape-relevant capability"
                    ),
                    pointer=".runArgs[" + str(i) + "]",
                    path=path,
                    hint=(
                        "--privileged, host-namespace sharing, and "
                        "cap-add=sys_admin dissolve the container's "
                        "isolation boundary; a compromised lifecycle "
                        "command (DC-001) at that privilege level is a "
                        "host compromise"
                    ),
                ))
                break
    return out


# ---------------------------------------------------------------------------
# Sensitive host-env exposure (DC-009).
# ---------------------------------------------------------------------------

_LOCAL_ENV_RE = re.compile(r"\$\{localEnv:([^}]+)\}", re.IGNORECASE)


def _check_local_env_exposure(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    scopes = (
        ("containerEnv", doc.get("containerEnv")),
        ("remoteEnv", doc.get("remoteEnv")),
    )
    for scope_name, scope in scopes:
        if not isinstance(scope, dict):
            continue
        for env_key, env_val in scope.items():
            if not isinstance(env_val, str):
                continue
            for m in _LOCAL_ENV_RE.finditer(env_val):
                host_var = m.group(1).strip().lower()
                if (host_var in options.sensitive_host_env
                        or host_var.endswith(options.sensitive_host_env_suffixes)):
                    out.append(Finding(
                        rule_id="DC-009",
                        severity=Severity.MEDIUM,
                        message=(
                            scope_name + "." + env_key
                            + " exposes host variable '" + m.group(1)
                            + "' into the container"
                        ),
                        pointer="." + scope_name + "." + env_key,
                        path=path,
                        hint=(
                            "A ${localEnv:...} reference to a credential-"
                            "shaped host variable (TOKEN, KEY, SECRET, "
                            "PASSWORD, cloud credentials) moves the "
                            "secret into the container's environment "
                            "where every lifecycle command and every "
                            "child process can read it"
                        ),
                    ))
                    break
    return out


# ---------------------------------------------------------------------------
# INFO rules (DC-011, DC-012).
# ---------------------------------------------------------------------------

def _check_root_user(doc, path, options):
    if not isinstance(doc, dict):
        return []
    if "remoteUser" in doc or "containerUser" in doc:
        return []
    return [Finding(
        rule_id="DC-011",
        severity=Severity.INFO,
        message=(
            "no remoteUser / containerUser; container processes run as "
            "root by default"
        ),
        pointer="<root>",
        path=path,
        hint=(
            "Setting remoteUser (and containerUser where applicable) to "
            "a non-root user limits the blast radius of a compromised "
            "lifecycle command"
        ),
    )]


def _check_missing_name(doc, path, options):
    if not isinstance(doc, dict):
        return []
    if isinstance(doc.get("name"), str) and doc["name"].strip():
        return []
    return [Finding(
        rule_id="DC-012",
        severity=Severity.INFO,
        message="devcontainer.json has no name field",
        pointer="<root>",
        path=path,
        hint=(
            "A name field at the document level anchors silent-change "
            "detection: a rename / repoint shows up in review"
        ),
    )]


# ---------------------------------------------------------------------------
# The registry. Order matters: DC-001 is the shared-contract anchor.
# ---------------------------------------------------------------------------

REGISTRY: List[Rule] = [
    Rule(
        id="DC-001",
        severity=Severity.HIGH,
        title="Lifecycle command fetches a remote script and pipes it to a shell",
        description=(
            "A lifecycle command containing curl / wget / Invoke-"
            "WebRequest piped into bash / sh / python / etc. runs "
            "whatever bytes the server returns on every container "
            "create or attach."
        ),
        check=_check_fetch_and_execute,
    ),
    Rule(
        id="DC-002",
        severity=Severity.HIGH,
        title="Lifecycle command installs from a VCS URL without a SHA pin",
        description=(
            "A pip install git+ / git clone from a URL that lacks an "
            "@<40-hex-SHA> pin is a mutable supply-chain source."
        ),
        check=_check_unpinned_install,
    ),
    Rule(
        id="DC-003",
        severity=Severity.HIGH,
        title="Feature reference not pinned by sha256 digest",
        description=(
            "A features entry (OCI image, Git URL, HTTP tarball) that "
            "lacks @sha256:<digest> or an @<40-hex-git-SHA> pin can "
            "silently move to new bytes."
        ),
        check=_check_feature_pinning,
    ),
    Rule(
        id="DC-004",
        severity=Severity.HIGH,
        title="Credential-shaped literal inlined under env / build / runArgs",
        description=(
            "JWTs, AWS access keys, GitHub tokens, PEM private-key "
            "headers, and bearer / api_key assignments inside "
            "containerEnv / remoteEnv / build.args / runArgs are "
            "shipped to every clone of the repository."
        ),
        check=_check_credential_literal,
    ),
    Rule(
        id="DC-005",
        severity=Severity.HIGH,
        title="Hidden-character class in any string value",
        description=(
            "Plane 14 Tags, bidi overrides, zero-width, mid-string "
            "BOM, control, and private-use codepoints are invisible to "
            "a human reviewer but reach the shell / tokenizer when the "
            "string is executed or displayed."
        ),
        check=_check_hidden_characters,
    ),
    Rule(
        id="DC-006",
        severity=Severity.MEDIUM,
        title="mounts bind-mounts a sensitive host path",
        description=(
            "A bind mount of the Docker socket, host home directory, "
            ".ssh / .aws / .gnupg, or filesystem root grants the "
            "container (and any lifecycle command) access to host "
            "credentials or privilege-escalation surfaces."
        ),
        check=_check_mounts,
    ),
    Rule(
        id="DC-007",
        severity=Severity.MEDIUM,
        title="runArgs grants a container-escape-relevant capability",
        description=(
            "--privileged, --pid=host / --net=host / --ipc=host, "
            "--userns=host, --cap-add=sys_admin, and "
            "--security-opt=seccomp=unconfined dissolve the "
            "container's isolation boundary."
        ),
        check=_check_privileged_runargs,
    ),
    Rule(
        id="DC-008",
        severity=Severity.MEDIUM,
        title="Lifecycle command writes to a shell init file",
        description=(
            "A redirect into .bashrc / .zshrc / .profile persists a "
            "mutation that is invisible to a reader of devcontainer."
            "json alone."
        ),
        check=_check_shell_init_write,
    ),
    Rule(
        id="DC-009",
        severity=Severity.MEDIUM,
        title="Sensitive host variable exposed through ${localEnv:...}",
        description=(
            "A containerEnv / remoteEnv entry that references a "
            "credential-shaped host variable (TOKEN, KEY, SECRET, "
            "PASSWORD, cloud credentials) moves the secret into the "
            "container environment."
        ),
        check=_check_local_env_exposure,
    ),
    Rule(
        id="DC-010",
        severity=Severity.MEDIUM,
        title="Image uses a mutable tag rather than a digest pin",
        description=(
            "An image field with a :latest / :main / :dev / :nightly "
            "tag resolves to whatever bytes the registry serves at "
            "pull time; a digest-pinned image is reproducible."
        ),
        check=_check_image_pinning,
    ),
    Rule(
        id="DC-011",
        severity=Severity.INFO,
        title="No remoteUser / containerUser (container runs as root)",
        description=(
            "Setting a non-root remoteUser limits the blast radius of "
            "a compromised lifecycle command."
        ),
        check=_check_root_user,
    ),
    Rule(
        id="DC-012",
        severity=Severity.INFO,
        title="devcontainer.json has no name field",
        description=(
            "A name field at the document level anchors silent-change "
            "detection: a rename / repoint shows up in review."
        ),
        check=_check_missing_name,
    ),
]


def run_all(doc: Any, path: str, options: Options) -> List[Finding]:
    out: List[Finding] = []
    for rule in REGISTRY:
        if not options.rule_enabled(rule.id):
            continue
        if rule.severity is Severity.INFO and not (
            options.strict or options.include_info
        ):
            continue
        out.extend(rule.check(doc, path, options))
    out.sort(key=lambda f: (f.path, f.pointer, f.rule_id))
    return out


__all__ = ["Rule", "Check", "REGISTRY", "run_all"]
