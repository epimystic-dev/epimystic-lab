# epimystic-lab

A continuously-updated workbench of small, useful, **governed** open-source contributions - and a daily research radar of the AI / ML / software frontier.

> Part of [Epimystic](https://epimystic.com) - a codex of the knowable and the unknowable.

## What this is

Each weekday-ish, a governed human-machine process scans the frontier (arXiv, Hacker News, trending repositories, daily papers), and - *when something is genuinely worth building* - produces one small, self-contained, tested artifact here: a focused tool, a clean-room reference implementation of one tractable result, a benchmark or evaluation harness. When nothing clears the bar, it ships **nothing but the radar entry** - restraint is the quality gate, not a failure.

Two things live here:

- **`projects/`** - dated, self-contained micro-projects. Each is independently licensed, tested, and documented; none is a flagship (deep work graduates to its own repository).
- **`research-radar/`** - a dated, curated digest of frontier signal: a few items each cycle with a one-line "why this matters," cited to source.

## The tools currently published

Small, offline, zero-dependency (stdlib-only) hygiene utilities. Each folder has its own README, tests, and LICENSE; click through for install and usage.

| Tool | What it does | Layer |
|---|---|---|
| [`jsonlcheck`](projects/2026-06-29_jsonlcheck/) | Strict streaming JSONL validator with `line:column` diagnostics | Data streams |
| [`jsonldiff`](projects/2026-07-05_jsonldiff/) | Semantic per-path diff for two JSONL streams | Data streams |
| [`jsonlsample`](projects/2026-07-12_jsonlsample/) | Deterministic reservoir / Bernoulli / stratified JSONL sampling | Data streams |
| [`envcheck`](projects/2026-07-05_envcheck/) | dotenv drift, syntax, and credential-pattern checker | Env & secrets |
| [`jwtcheck`](projects/2026-07-12_jwtcheck/) | JWT / auth-secret hygiene linter for `.env` files | Env & secrets |
| [`reqcheck`](projects/2026-07-19_reqcheck/) | Offline supply-chain linter for pip `requirements.txt` | Install manifests |
| [`licensechain`](projects/2026-07-26_licensechain/) | Offline license-chain linter for `dataset -> model -> app` supply | Install manifests |
| [`aicontribcheck`](projects/2026-08-02_aicontribcheck/) | Offline AI-contribution-policy detector for a repo checkout | Repo policy |
| [`skillcheck`](projects/2026-08-09_skillcheck/) | Offline safety linter for agent skill files (SKILL.md / AGENTS.md / skills/ / *.skill.md) | Agent skills |
| [`seedline`](projects/2026-06-29_seedline/) | One `seed_all(n)` that seeds Python / NumPy / PyTorch RNGs | Reproducibility (lib) |

## How it is made (and what that means)

Every artifact here is produced by **a human-machine hybrid intelligence, rooted in ethics and philosophy**, and passes - *before* it is published - an external, deterministic policy gate and an independent maker-checker review:

- a **de-brand / secret gate** (no vendor lock, no leaked credentials),
- a **clean-room rule** (a paper's *method* is read; never the authors' reference code),
- **tests green**, and
- a **claims-substantiation pass** (a number or a "novel" claim is reproduced-with-evidence or removed).

The gate runs *outside* the builder - the builder proposes, a deterministic harness disposes. A passing gate means **"origin-valid, content-unverified," never "verified-safe."** This discipline is itself the point: it is a working instance of the governance architecture published as [`indras-net`](https://github.com/epimystic-dev/indras-net).

## Honest scope

This is a **research-and-utility lab**, not a product. Artifacts are small by design; reimplementations of published work are *independent implementations*, cited and **not affiliated with or endorsed by the original authors**. Use accordingly, and read each project's own README and LICENSE.

## License

Each `projects/` artifact carries its own LICENSE (permissive by default). The radar and this index are Apache-2.0 unless noted.

---

*Produced by Epimystic, a human-machine hybrid intelligence, under maker-checker.*
