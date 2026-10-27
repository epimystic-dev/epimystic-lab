"""Rule registry for renovatelint.

Twelve shape defects on the Renovate bot config surface. Rule IDs use
the ``RNV-`` prefix (Renovate); the lab-wide shared surface exposes
this list as ``ALL_RULES``.

The attack family is grounded in:

- The public Renovate documentation
  (https://docs.renovatebot.com/configuration-options/ and
  https://docs.renovatebot.com/presets-config/), which names
  ``enabled``, ``automerge``, ``minimumReleaseAge``, ``extends``,
  ``hostRules``, ``allowedPostUpgradeCommands``, ``vulnerabilityAlerts``,
  ``osvVulnerabilityAlerts``, ``packageRules``, ``matchUpdateTypes``,
  ``$schema``, and ``timezone`` as the fields a config file writes.
- The 2026 Renovate security-mode community posture (Compass Security
  2025-05 "Renovate - keeping your updates secure"; safeguard.sh 2026
  "Renovate 2026 Security Mode Field Test" and "Renovate Bot
  Configuration Recipes for 2026"; systemshardening.com "Renovate and
  Dependabot Security Configuration: Auto-Merge Boundaries and Scope
  Rules"), which names ``minimumReleaseAge: 14 days`` as the
  recommended quarantine window and names unguarded auto-merge as the
  dominant fault class the config can prevent.
- The October 21 2026 LiteLLM supply-chain attack (Help Net Security
  2026-10-22, Socket 2026-10, SOCRadar 2026-10, Aviatrix 2026-10):
  a trojanized LiteLLM 1.107.0 wheel on PyPI (and Docker Hub tags)
  that harvested cloud credentials from ~49,000 installs during an
  ~104-minute exposure window before yank; a 14-day quarantine would
  have blocked any Renovate PR from auto-merging the malicious release.

The rules are shape-only: a renovate config is a developer-authored
artifact that lives on disk; shape defects at that layer are detectable
statically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Tuple

from .parse import parse_duration_days
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
# Document shape helpers.
# ---------------------------------------------------------------------------

def _package_rules(doc: Any) -> List[Any]:
    if not isinstance(doc, dict):
        return []
    pr = doc.get("packageRules")
    if isinstance(pr, list):
        return pr
    return []


def _any_automerge_true(doc: Any) -> bool:
    """Does any config path assert automerge: true? Walks root and
    packageRules; the Renovate schema also allows automerge inside
    nested matchers, which we treat as covered by the packageRules
    walk since real configs put the flag at that level."""
    if not isinstance(doc, dict):
        return False
    if doc.get("automerge") is True:
        return True
    for entry in _package_rules(doc):
        if isinstance(entry, dict) and entry.get("automerge") is True:
            return True
    return False


def _config_has_min_release_age(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if doc.get("minimumReleaseAge") not in (None, ""):
        return True
    for entry in _package_rules(doc):
        if isinstance(entry, dict) and entry.get("minimumReleaseAge") not in (None, ""):
            return True
    return False


# ---------------------------------------------------------------------------
# RNV-001  enabled: false
# ---------------------------------------------------------------------------

def _check_disabled(doc, path, options):
    if not isinstance(doc, dict):
        return []
    if doc.get("enabled") is False:
        return [Finding(
            rule_id="RNV-001",
            severity=Severity.HIGH,
            message=(
                "enabled is false at the document root; the whole "
                "config is silently disabled"
            ),
            pointer=".enabled",
            path=path,
            hint=(
                "A top-level 'enabled: false' turns Renovate off for "
                "this repository: no vulnerability-driven PRs, no "
                "update PRs, no audit trail of inaction. If the "
                "intent is to pause temporarily use a scheduled "
                "window; if the intent is to disable permanently "
                "remove the file so the state is visible in review"
            ),
        )]
    return []


# ---------------------------------------------------------------------------
# RNV-002  root automerge: true without minimumReleaseAge
# ---------------------------------------------------------------------------

def _check_root_automerge_no_quarantine(doc, path, options):
    if not isinstance(doc, dict):
        return []
    if doc.get("automerge") is not True:
        return []
    if _config_has_min_release_age(doc):
        return []
    return [Finding(
        rule_id="RNV-002",
        severity=Severity.HIGH,
        message=(
            "root automerge:true is set with no minimumReleaseAge "
            "configured anywhere (unguarded auto-merge)"
        ),
        pointer=".automerge",
        path=path,
        hint=(
            "Without a quarantine window Renovate can auto-merge a "
            "release the registry has not had time to yank: the "
            "October 2026 LiteLLM supply-chain attack (~49k installs "
            "of a trojanized wheel during a 104-minute window) is the "
            "shape this rule is sized against. Set "
            "minimumReleaseAge to '14 days' at the document root or "
            "in every automerge-enabled packageRule"
        ),
    )]


# ---------------------------------------------------------------------------
# RNV-003  extends preset without a #tag or @sha pin
# ---------------------------------------------------------------------------

_FORTY_HEX = re.compile(r"@[0-9a-f]{40}\b")
# Renovate preset refs use `preset#tag` and `preset#<40-hex-sha>` to
# pin version. Any `#` suffix is accepted as a pin; we insist only on
# the presence of the delimiter for the shape rule and let the user
# decide between tag and SHA.
_PINNED_PRESET = re.compile(r"[#@][\w\d._\-/]+$")

# A built-in config (shipped with Renovate itself) is always safe to
# use unpinned because its contents move only with Renovate's own
# published version.
_BUILTIN_PREFIXES = (
    "config:", "default:", "docker:", "monorepo:", "schedule:",
    "helpers:", "group:", "preview:", "replacements:", "regexManagers:",
    "security:", "workarounds:", "mergeConfidence:", "npm:", "github>renovatebot/",
)


def _extends_is_builtin(name: str) -> bool:
    low = name.strip().lower()
    for prefix in _BUILTIN_PREFIXES:
        if low.startswith(prefix.lower()):
            return True
    return False


def _extends_is_repo_ref(name: str) -> bool:
    """Match the ``platform>owner/repo`` or ``owner/repo`` form that
    pulls a preset from a non-built-in source."""
    s = name.strip()
    if s.startswith(("github>", "gitlab>", "gitea>", "bitbucket>", "local>", "forgejo>")):
        return True
    if "/" in s and not s.startswith(("http://", "https://", "git+")):
        # A bare owner/repo without an explicit platform prefix.
        return True
    if s.startswith(("http://", "https://", "git+")):
        return True
    return False


def _check_extends_pinning(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    extends = doc.get("extends")
    if not isinstance(extends, list):
        return out
    for i, name in enumerate(extends):
        if not isinstance(name, str):
            continue
        s = name.strip()
        if not s:
            continue
        if _extends_is_builtin(s):
            continue
        if not _extends_is_repo_ref(s):
            continue
        # `local>owner/config` is a repo on the host SCM; the lab's
        # charter still treats it as a mutable source worth flagging
        # unless the user has pinned it.
        if "#" in s or _FORTY_HEX.search(s):
            continue
        out.append(Finding(
            rule_id="RNV-003",
            severity=Severity.HIGH,
            message=(
                "extends[" + str(i) + "] = '" + s + "' is a repo "
                "preset without a #<tag> or @<40-hex-sha> pin "
                "(mutable supply-chain source)"
            ),
            pointer=".extends[" + str(i) + "]",
            path=path,
            hint=(
                "A repo preset without a pin resolves to whatever "
                "the latest commit on the default branch happens to "
                "be at Renovate run time. Pin with 'github>owner/"
                "config#v1' or 'github>owner/config#<40-hex-sha>' "
                "so the preset reviewed in the PR is the preset "
                "the bot actually executed"
            ),
        ))
    return out


# ---------------------------------------------------------------------------
# RNV-004  credential-shaped literal
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


# Keys that commonly inline a credential if misconfigured.
_CRED_SCOPE_KEYS = (
    "hostRules",
    "token",
    "repositoryToken",
    "env",
    "customEnvVariables",
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
                rule_id="RNV-004",
                severity=Severity.HIGH,
                message=(
                    "credential-shaped literal (" + label + ") "
                    "inlined under " + scope_key
                ),
                pointer="." + pointer,
                path=path,
                hint=(
                    "A credential committed to a Renovate config is "
                    "shipped to every clone of the repository and "
                    "every CI job that reads the config. Replace the "
                    "literal with an environment variable the Renovate "
                    "process reads at run time, and rotate the "
                    "exposed credential immediately"
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# RNV-005  allowedPostUpgradeCommands pipes fetch-and-exec
# ---------------------------------------------------------------------------

_FETCH_AND_EXECUTE = re.compile(
    r"\b(curl|wget|fetch|iwr|invoke-webrequest)\b[^\n;|]*?\|\s*"
    r"(sh|bash|zsh|dash|ash|ksh|pwsh|powershell|python|python3|node|ruby|perl)\b",
    re.IGNORECASE,
)
_EXEC_REMOTE = re.compile(
    r"\b(bash|sh|zsh|dash|ksh|pwsh|powershell)\b\s+-c\s+[\"']\$\(\s*(curl|wget|iwr)\b",
    re.IGNORECASE,
)
_PROCESS_SUB_REMOTE = re.compile(
    r"\b(bash|sh|zsh|dash|ksh)\b\s+<\(\s*(curl|wget)\b",
    re.IGNORECASE,
)


def _check_fetch_and_exec(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    cmds = doc.get("allowedPostUpgradeCommands")
    if not isinstance(cmds, list):
        return out
    for i, cmd in enumerate(cmds):
        if not isinstance(cmd, str):
            continue
        if (_FETCH_AND_EXECUTE.search(cmd)
                or _EXEC_REMOTE.search(cmd)
                or _PROCESS_SUB_REMOTE.search(cmd)):
            out.append(Finding(
                rule_id="RNV-005",
                severity=Severity.HIGH,
                message=(
                    "allowedPostUpgradeCommands[" + str(i) + "] pipes "
                    "a network fetch into a shell interpreter"
                ),
                pointer=".allowedPostUpgradeCommands[" + str(i) + "]",
                path=path,
                hint=(
                    "An allowed post-upgrade command that curls a URL "
                    "and pipes it into a shell runs whatever bytes "
                    "the server returns on every Renovate update run. "
                    "Replace with a vendored script committed to the "
                    "repo, or a package-manager invocation with a "
                    "pinned signature"
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# RNV-006  hidden-character class in any string
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
                rule_id="RNV-006",
                severity=Severity.MEDIUM,
                message=(
                    "string value contains " + label + " character "
                    "U+%04X at offset " % cp + str(idx)
                ),
                pointer="." + pointer,
                path=path,
                hint=(
                    "Hidden-character classes (Plane 14 TAG, bidi "
                    "overrides, zero-width, control, PUA) are "
                    "invisible to a human reviewer but reach the "
                    "shell / tokenizer / parser when the string is "
                    "executed, displayed, or matched. Strip them or "
                    "reject the value"
                ),
            ))
            break
    return out


# ---------------------------------------------------------------------------
# RNV-007  packageRules automerge without matchUpdateTypes
# ---------------------------------------------------------------------------

# A matchUpdateTypes list that narrows auto-merge to safe update kinds.
# "patch", "pin", "digest", "lockFileMaintenance" are the safe set the
# 2026 security-mode posture names; "minor" and "major" are the
# over-broad cases this rule treats as unscoped.
_NARROWING_UPDATE_TYPES = frozenset(
    ["patch", "pin", "digest", "lockFileMaintenance", "pinDigest"]
)


def _check_packagerules_automerge_scope(doc, path, options):
    out: List[Finding] = []
    for i, entry in enumerate(_package_rules(doc)):
        if not isinstance(entry, dict):
            continue
        if entry.get("automerge") is not True:
            continue
        mut = entry.get("matchUpdateTypes")
        if isinstance(mut, list) and mut:
            # Narrowing lists must contain only safe update types.
            if all(isinstance(t, str) and t.lower() in _NARROWING_UPDATE_TYPES
                   for t in mut):
                continue
            # If the list carries 'minor' or 'major', it is NOT narrow
            # enough for an automerge rule; the finding still fires.
        out.append(Finding(
            rule_id="RNV-007",
            severity=Severity.MEDIUM,
            message=(
                "packageRules[" + str(i) + "] enables automerge "
                "without a matchUpdateTypes restriction to a safe "
                "subset (patch / pin / digest / lockFileMaintenance)"
            ),
            pointer=".packageRules[" + str(i) + "]",
            path=path,
            hint=(
                "An unscoped automerge rule auto-merges every "
                "update type that matches the other predicates, "
                "including major-version bumps where breaking "
                "changes land. Narrow with matchUpdateTypes: "
                "['patch', 'pin', 'digest'] or move the rule under "
                "a package subset where a major bump is still safe"
            ),
        ))
    return out


# ---------------------------------------------------------------------------
# RNV-008  vulnerabilityAlerts.enabled: false
# ---------------------------------------------------------------------------

def _check_vulnerability_alerts(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    va = doc.get("vulnerabilityAlerts")
    if isinstance(va, dict) and va.get("enabled") is False:
        out.append(Finding(
            rule_id="RNV-008",
            severity=Severity.MEDIUM,
            message=(
                "vulnerabilityAlerts.enabled is false; "
                "vulnerability-driven PRs are silently off"
            ),
            pointer=".vulnerabilityAlerts.enabled",
            path=path,
            hint=(
                "Disabling vulnerability alerts also disables the "
                "security preset's label-and-expedite behaviour, so "
                "a CVE affecting a transitive dependency produces no "
                "Renovate PR at all. Prefer leaving the alerts "
                "enabled and controlling noise through "
                "prConcurrentLimit or a dedicated schedule window"
            ),
        ))
    if doc.get("osvVulnerabilityAlerts") is False:
        out.append(Finding(
            rule_id="RNV-008",
            severity=Severity.MEDIUM,
            message=(
                "osvVulnerabilityAlerts is false; the OSV.dev parallel "
                "vulnerability source is silently off"
            ),
            pointer=".osvVulnerabilityAlerts",
            path=path,
            hint=(
                "The osvVulnerabilityAlerts option (Renovate 2026 "
                "security-mode) adds OSV.dev as a second vulnerability "
                "source; disabling it leaves alerts dependent on the "
                "host SCM's advisory feed alone. Prefer leaving it "
                "enabled"
            ),
        ))
    return out


# ---------------------------------------------------------------------------
# RNV-009  allowedPostUpgradeCommands has non-empty entries
# ---------------------------------------------------------------------------

def _check_post_upgrade_surface(doc, path, options):
    """A non-empty allowedPostUpgradeCommands list is an execution
    surface and warrants review even when none of the commands pipe
    fetch-and-exec. Rule fires MEDIUM; RNV-005 escalates to HIGH when
    the specific fetch-and-exec shape is present."""
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    cmds = doc.get("allowedPostUpgradeCommands")
    if not isinstance(cmds, list) or not cmds:
        return out
    non_empty = [c for c in cmds if isinstance(c, str) and c.strip()]
    if not non_empty:
        return out
    out.append(Finding(
        rule_id="RNV-009",
        severity=Severity.MEDIUM,
        message=(
            "allowedPostUpgradeCommands has " + str(len(non_empty))
            + " non-empty entries; execution surface requires review"
        ),
        pointer=".allowedPostUpgradeCommands",
        path=path,
        hint=(
            "Every entry in allowedPostUpgradeCommands runs under the "
            "Renovate worker's privileges on every matching update. "
            "Treat the list as code-review surface: inline the "
            "command definition, keep it minimal, and pair it with "
            "RNV-005 (fetch-and-exec) and RNV-007 (automerge scope) "
            "to bound the blast radius"
        ),
    ))
    return out


# ---------------------------------------------------------------------------
# RNV-010  minimumReleaseAge set but below quarantine floor
# ---------------------------------------------------------------------------

def _check_quarantine_too_short(doc, path, options):
    out: List[Finding] = []
    if not isinstance(doc, dict):
        return out
    sites: List[Tuple[str, Any]] = []
    if "minimumReleaseAge" in doc:
        sites.append((".minimumReleaseAge", doc.get("minimumReleaseAge")))
    for i, entry in enumerate(_package_rules(doc)):
        if not isinstance(entry, dict):
            continue
        if "minimumReleaseAge" in entry:
            sites.append((
                ".packageRules[" + str(i) + "].minimumReleaseAge",
                entry.get("minimumReleaseAge"),
            ))
    for pointer, value in sites:
        days = parse_duration_days(value)
        if days is None:
            continue
        if days < options.min_quarantine_days:
            out.append(Finding(
                rule_id="RNV-010",
                severity=Severity.MEDIUM,
                message=(
                    "minimumReleaseAge is " + repr(value) + " ("
                    + "%.2f days" % days + "), shorter than the "
                    + str(options.min_quarantine_days)
                    + "-day industry recommendation"
                ),
                pointer=pointer,
                path=path,
                hint=(
                    "A quarantine window shorter than ~7 days is too "
                    "short to reliably catch a malicious release that "
                    "the registry yanks within hours or days: the "
                    "October 2026 LiteLLM wheel was live for only "
                    "~104 minutes but the yank-and-advisory window "
                    "stretched across days. Prefer '14 days' (Compass "
                    "Security / safeguard.sh 2026 recommendation)"
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# RNV-011  missing $schema
# ---------------------------------------------------------------------------

_RENOVATE_SCHEMA_HINTS = (
    "renovate",
    "renovate-schema",
)


def _check_missing_schema(doc, path, options):
    if not isinstance(doc, dict):
        return []
    s = doc.get("$schema")
    if isinstance(s, str) and any(h in s.lower() for h in _RENOVATE_SCHEMA_HINTS):
        return []
    return [Finding(
        rule_id="RNV-011",
        severity=Severity.INFO,
        message=(
            "no $schema reference; editor-time validation of the "
            "config shape is unavailable"
        ),
        pointer="<root>",
        path=path,
        hint=(
            "Setting $schema to https://docs.renovatebot.com/"
            "renovate-schema.json lets editors catch typos and "
            "unknown options before Renovate parses the file"
        ),
    )]


# ---------------------------------------------------------------------------
# RNV-012  missing timezone
# ---------------------------------------------------------------------------

def _check_missing_timezone(doc, path, options):
    if not isinstance(doc, dict):
        return []
    tz = doc.get("timezone")
    if isinstance(tz, str) and tz.strip():
        return []
    return [Finding(
        rule_id="RNV-012",
        severity=Severity.INFO,
        message=(
            "no timezone field; schedule windows resolve against "
            "UTC which may drift from the maintainer's intent"
        ),
        pointer="<root>",
        path=path,
        hint=(
            "Setting timezone (e.g. 'UTC' or 'America/New_York') "
            "makes schedule windows reproducible across runs and "
            "across contributors in different regions"
        ),
    )]


# ---------------------------------------------------------------------------
# Registry. Order matters: RNV-001 is the shared-contract anchor.
# ---------------------------------------------------------------------------

REGISTRY: List[Rule] = [
    Rule(
        id="RNV-001",
        severity=Severity.HIGH,
        title="enabled:false silently disables the whole config",
        description=(
            "A top-level `enabled: false` disables Renovate for the "
            "repository: no vulnerability-driven PRs, no update PRs, "
            "no audit trail of inaction. Visible-in-review by inverting "
            "the sentinel - a deleted file is louder than a disabled one."
        ),
        check=_check_disabled,
    ),
    Rule(
        id="RNV-002",
        severity=Severity.HIGH,
        title="root automerge:true with no minimumReleaseAge quarantine",
        description=(
            "Root `automerge: true` without `minimumReleaseAge` set "
            "anywhere lets Renovate auto-merge a release before the "
            "registry has time to yank a malicious one. The October 2026 "
            "LiteLLM supply-chain attack is the shape this rule is "
            "sized against."
        ),
        check=_check_root_automerge_no_quarantine,
    ),
    Rule(
        id="RNV-003",
        severity=Severity.HIGH,
        title="extends preset without a #<tag> or @<sha> pin",
        description=(
            "A repo-sourced preset (`github>owner/config`, "
            "`gitlab>owner/config`, etc.) without a `#<tag>` or "
            "`@<40-hex-sha>` pin resolves to the default branch's "
            "current contents at Renovate run time."
        ),
        check=_check_extends_pinning,
    ),
    Rule(
        id="RNV-004",
        severity=Severity.HIGH,
        title="Credential-shaped literal inlined in the config",
        description=(
            "JWTs, AWS access keys, GitHub tokens, PEM private-key "
            "headers, and bearer / api-key assignments inside "
            "hostRules / token / repositoryToken / env / "
            "customEnvVariables are shipped to every clone of the "
            "repository and read by every CI job."
        ),
        check=_check_credential_literal,
    ),
    Rule(
        id="RNV-005",
        severity=Severity.HIGH,
        title="allowedPostUpgradeCommands pipes fetch-and-exec",
        description=(
            "An entry in allowedPostUpgradeCommands containing curl / "
            "wget / Invoke-WebRequest piped into bash / sh / python "
            "runs whatever bytes the server returns on every Renovate "
            "post-upgrade pass."
        ),
        check=_check_fetch_and_exec,
    ),
    Rule(
        id="RNV-006",
        severity=Severity.MEDIUM,
        title="Hidden-character class in any string value",
        description=(
            "Plane 14 Tags, bidi overrides, zero-width, mid-string "
            "BOM, control, and private-use codepoints are invisible to "
            "a human reviewer but reach the shell / parser / tokenizer "
            "when the string is executed, displayed, or matched."
        ),
        check=_check_hidden_characters,
    ),
    Rule(
        id="RNV-007",
        severity=Severity.MEDIUM,
        title="packageRules automerge without matchUpdateTypes scope",
        description=(
            "A packageRules entry with `automerge: true` and no "
            "`matchUpdateTypes` restriction (or a list that includes "
            "'minor' / 'major') auto-merges every matching update "
            "type, including major bumps where breaking changes land."
        ),
        check=_check_packagerules_automerge_scope,
    ),
    Rule(
        id="RNV-008",
        severity=Severity.MEDIUM,
        title="vulnerabilityAlerts.enabled:false or osvVulnerabilityAlerts:false",
        description=(
            "Explicitly disabling vulnerability alerts (either the "
            "host SCM feed or the OSV.dev parallel source) silently "
            "drops the security-driven PR path."
        ),
        check=_check_vulnerability_alerts,
    ),
    Rule(
        id="RNV-009",
        severity=Severity.MEDIUM,
        title="allowedPostUpgradeCommands has non-empty entries",
        description=(
            "A non-empty allowedPostUpgradeCommands list is an "
            "execution surface that warrants explicit review even "
            "when no entry pipes fetch-and-exec."
        ),
        check=_check_post_upgrade_surface,
    ),
    Rule(
        id="RNV-010",
        severity=Severity.MEDIUM,
        title="minimumReleaseAge set but shorter than the quarantine floor",
        description=(
            "A minimumReleaseAge below the 7-day industry "
            "recommendation (Compass Security / safeguard.sh 2026) is "
            "too short to reliably outlast a yank-and-advisory window."
        ),
        check=_check_quarantine_too_short,
    ),
    Rule(
        id="RNV-011",
        severity=Severity.INFO,
        title="No $schema reference",
        description=(
            "Setting `$schema` to the published Renovate schema URL "
            "lets editors catch typos and unknown options at author "
            "time."
        ),
        check=_check_missing_schema,
    ),
    Rule(
        id="RNV-012",
        severity=Severity.INFO,
        title="No timezone field",
        description=(
            "Without a `timezone` entry schedule windows resolve "
            "against UTC, which may drift from the maintainer's intent "
            "and across contributors in different regions."
        ),
        check=_check_missing_timezone,
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
