# devcontainercheck

Static linter for **devcontainer.json** files - the config a VS Code
Dev Container, a GitHub Codespace, or a Dev Containers CLI consumer
reads to create a reproducible development environment. Flags twelve
shape defects enabling supply-chain, lifecycle-command, and host-escape
attacks against that boundary.

Zero dependencies. Python 3.10+. MIT licensed. Offline, deterministic,
shape-only.

## Why

A devcontainer.json carries lifecycle commands that execute when the
container is created or attached - six slots (`initializeCommand`,
`onCreateCommand`, `updateContentCommand`, `postCreateCommand`,
`postStartCommand`, `postAttachCommand`) that run with the container's
privilege. VS Code's Workspace Trust gate exists precisely because
these slots are a supply-chain surface: once a folder is marked
trusted, the commands run on every open; GitHub Codespaces and the
Dev Containers CLI run them unconditionally.

The October 2026 `GhostAction` campaign (reported 2026-10-07 to
2026-10-09 by The Hacker News, GitGuardian, Socket, Datadog Security
Labs, Aviatrix) escalated this fault class across tens of thousands of
repositories: tag-pinned install commands and credential-exposing CI
configurations exfiltrated maintainer secrets at scale. The same
mutable-tag / fetch-and-exec / credential-inline shapes that gated the
GitHub Actions campaign gate the devcontainer.json boundary too.

`devcontainercheck` is the small offline pre-flight that catches those
shapes in the artifact a developer already has on disk, *before* the
container runs.

## Scope and limits

- **Shape-only.** The linter reads the file off disk and inspects its
  structure; it does not run the container, does not fetch anything,
  does not resolve referenced images or features, and does not claim
  that a healthy verdict means the resulting container is runtime-safe
  (`origin-valid, content-unverified`).
- **Independent implementation**, not affiliated with or endorsed by
  Microsoft, the containers.dev working group, or any of the cited
  security publications.
- **No runtime guarantees.** Rules fire on the rung-1 pattern surface
  (per the Pearl ladder); rung-2 interventional closure and rung-3
  counterfactual guarantees are out of scope for a static linter.

## Install

```bash
python -m pip install -e .
```

Or run directly without installing:

```bash
python -m devcontainercheck /path/to/.devcontainer/devcontainer.json
```

Requires Python 3.10+. No dependencies.

## Use

```bash
devcontainercheck .devcontainer/devcontainer.json       # one file
devcontainercheck .devcontainer/                        # directory walk
devcontainercheck --json .devcontainer/devcontainer.json
devcontainercheck --strict .devcontainer/devcontainer.json
devcontainercheck --include-info .devcontainer/devcontainer.json
devcontainercheck --disable DC-012 .devcontainer/devcontainer.json
devcontainercheck --only DC-001 .devcontainer/devcontainer.json
```

The exit code reflects the verdict:

| Verdict           | rc | Meaning |
|---                |---:|---|
| `healthy`         | 0  | No findings, or INFO only without `--strict`. |
| `needs-attention` | 1  | Any MEDIUM, or INFO under `--strict`. |
| `unhealthy`       | 2  | Any HIGH. |
| `unknown`         | 1 (`2` under `--strict`) | No files scanned. |

## File shapes accepted

- Plain JSON `.devcontainer/devcontainer.json`.
- JSONC (JSON with `//` line comments, `/* ... */` block comments, and
  trailing commas) - the shape Microsoft's VS Code implementation
  accepts.
- A directory walk accepts both the standard
  `.devcontainer/devcontainer.json` location and the multi-config
  `.devcontainer/<name>.devcontainer.json` form.

## Rules

5 HIGH / 5 MEDIUM / 2 INFO. INFO is suppressed unless `--include-info`
or `--strict` is passed.

| ID       | Severity | What it flags |
|---       |---       |---            |
| DC-001   | HIGH     | Lifecycle command pipes a network fetch (curl / wget / Invoke-WebRequest) into a shell interpreter. Runs whatever bytes the server returns on every container create or attach. |
| DC-002   | HIGH     | Lifecycle command installs from a VCS URL (`pip install git+`, `git clone`) without an `@<40-hex-SHA>` commit pin. Mutable supply-chain source. |
| DC-003   | HIGH     | `features` entry references an OCI image / Git URL / HTTP tarball without an `@sha256:<digest>` or `@<40-hex-git-SHA>` pin. |
| DC-004   | HIGH     | Credential-shaped literal (JWT, AWS access key, GitHub token, PEM private-key header, bearer / api_key assignment) inlined under `containerEnv` / `remoteEnv` / `build.args` / `runArgs`. |
| DC-005   | HIGH     | Hidden-character class (Plane 14 TAG `U+E0000-U+E007F`, bidi override, zero-width, mid-string BOM, C0/C1 control, private-use) in any string value. Invisible to a human reviewer but reaches the shell / tokenizer. |
| DC-006   | MEDIUM   | `mounts` bind-mounts a sensitive host path (Docker socket, home `.ssh` / `.aws` / `.gnupg` / `.kube`, filesystem root). |
| DC-007   | MEDIUM   | `runArgs` grants a container-escape-relevant capability (`--privileged`, `--pid=host`, `--net=host`, `--cap-add=sys_admin`, `--security-opt=seccomp=unconfined`). |
| DC-008   | MEDIUM   | Lifecycle command writes to a shell init file (`.bashrc`, `.zshrc`, `.profile`). Persistent dotfile mutation invisible to a reader of devcontainer.json alone. |
| DC-009   | MEDIUM   | `containerEnv` / `remoteEnv` exposes a sensitive host variable through `${localEnv:...}` (TOKEN, KEY, SECRET, cloud credentials). |
| DC-010   | MEDIUM   | `image` references a mutable tag (`:latest` / `:main` / `:dev` / `:nightly`) rather than `@sha256:<digest>`. |
| DC-011   | INFO     | No `remoteUser` / `containerUser`; container processes run as root by default. |
| DC-012   | INFO     | Missing `name` field at the document level. Silent-change detection surface. |

### External-source and sensitive-path vocabularies

DC-006 and DC-009 depend on two vocabularies the Options object
carries:

- **sensitive_host_paths** (default): `/`, `/root`, `/home`,
  `/var/run/docker.sock`, `/run/docker.sock`, `.ssh`, `.aws`,
  `.gnupg`, `.docker`, `.kube`, `.config/gcloud`, `.config/gh`,
  `.netrc`, `_netrc`.
- **sensitive_host_env** (default): `api_key`, `apikey`, `api_token`,
  `token`, `secret`, `password`, `passwd`, `pass`, AWS
  (`aws_access_key_id`, `aws_secret_access_key`, `aws_session_token`),
  GitHub (`github_token`, `gh_token`), package registries (`npm_token`,
  `pypi_token`, `cargo_token`), model hubs (`hf_token`, `huggingface_token`),
  and any host variable whose name ends in a credential-shaped suffix (`_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD` and similar - the full list is `sensitive_host_env_suffixes` in `types.py`), which covers vendor keys no fixed list could enumerate. Others named explicitly:
  (`docker_password`, `slack_token`, `gitlab_token`, `circle_token`).

A store that spelled a sensitive host variable with a different name
(e.g. `MY_COMPANY_SPECIFIC_TOKEN`) will not trigger DC-009; the
vocabulary is intentionally conservative to keep false positives low.

## Example

```bash
$ cat .devcontainer/devcontainer.json
{
  "image": "python:latest",
  "features": { "ghcr.io/devcontainers/features/node:1": {} },
  "postCreateCommand": "curl -fsSL https://example.com/install.sh | bash",
  "mounts": ["source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"],
  "runArgs": ["--privileged"]
}

$ devcontainercheck .devcontainer/devcontainer.json
HIGH DC-001 .../devcontainer.json .postCreateCommand: lifecycle command pipes a network fetch into a shell interpreter
    hint: ...
HIGH DC-003 .../devcontainer.json .features.ghcr.io/.../node:1: feature reference ... is not pinned by sha256 digest (mutable tag)
    hint: ...
MEDIUM DC-006 .../devcontainer.json .mounts[0]: mounts[0] bind-mounts sensitive host path '/var/run/docker.sock'
    hint: ...
MEDIUM DC-007 .../devcontainer.json .runArgs[0]: runArgs[0] = '--privileged' grants a container-escape-relevant capability
    hint: ...
MEDIUM DC-010 .../devcontainer.json .image: image 'python:latest' uses a mutable tag; pin to @sha256:<digest> for reproducibility
    hint: ...
devcontainercheck: unhealthy; files=1 findings=5
```

The healthy sibling (`examples/healthy_devcontainer.json`) exits 0.

## Clean-room provenance

Rules are derived from the public containers.dev specification, from
the public VS Code Workspace Trust documentation, from the public news
coverage of the October 2026 GhostAction campaign, and from
long-published public shape conventions for OCI image references,
VCS install pinning, and dotfile-shell-init paths. No reference
linter implementation was read, vendored, or mirrored. Rule semantics
are shape-only.

## Tests

```bash
python -m unittest discover -s tests
```

Positive-and-negative discrimination for every rule; shared
package-surface contract against the lab's CONVENTIONS.md; a
`PYTHONIOENCODING=cp1252` subprocess test that pins the no-traceback
and `<U+XXXX>` rendering invariants against both text and JSON output.

## Attribution

Produced by Epimystic, a human-machine hybrid intelligence, under
maker-checker.
