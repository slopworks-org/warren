# Warren — rules for Claude Code

Self-hosted WireGuard hub plus HTTPS reverse proxy: a server for one VPS and a
tiny agent for routers. See README.md for what it does and how it works.

## Layout

```
crates/
  proto/   agent↔server wire formats, tokens, HMAC; dependency-light, shared with the agent
  wgctl/   hand-written netlink control of WireGuard, links and addresses (libc only, Linux)
  agent/   the `warren` binary
  server/  the `warren-server` binary and library: API, web admin, proxy, ACME, hub
    web/   admin UI (HTML/JS/CSS), embedded into the binary with include_str!
    tests/ e2e.rs, the end-to-end test (ignored by default, run by scripts/e2e.sh)
docs/      README diagram, light and dark variants
dist/      config sample, systemd units, OpenWrt init scripts, Dockerfiles
scripts/   build, packaging, Linux container and gate scripts
```

## Conventions

- Rust toolchain pinned in `.tool-versions`; `source env.sh` puts it on PATH in
  non-interactive shells.
- The agent is size-critical: it depends only on `std`, `libc`, `x25519-dalek`
  and `warren-proto`, and is built with `--profile agent`. Don't add
  dependencies to it, or to `proto`/`wgctl`, which it links.
- Workspace lints are strict (clippy `pedantic`, no `unwrap`/`expect`/`panic`
  outside tests, `missing_docs`); the gate runs clippy with `-D warnings`.
  Silence a lint only locally, with a comment saying why.
- Netlink, TUN and the e2e test are Linux-only. On macOS run them through
  `just linux <command>` (a privileged container).

## Commands

- `just` lists every command; each recipe is a thin wrapper over `scripts/`.
  CI and lefthook call `scripts/check.sh` directly, so keep the logic in the
  scripts.
- Gate: `just check` = format + clippy + test; one step: `just check clippy`.
- Linux gate on macOS: `just check-linux`; any command in the container:
  `just linux <command>`.
- Pre-commit: `lefthook install` sets up a hook with the same gate;
  `LEFTHOOK=0 git commit` skips it once.
- Format: `just fmt`.
- End-to-end test: `just e2e` (Docker).
- Builds: `just agent [aarch64|armv7|x86_64 ...]`, `just server [amd64|arm64]`,
  `just ipk`; output in `dist/out/`.

### Definition of done

- **Everything in the repo is written in English** — code, comments, docs, commit messages, issues and PRs (title and body), whatever language the task was discussed in. The only exception is localization: translations into other languages.
- **Never commit to main.** Every task starts on a fresh branch off `origin/main`, named `<type>/<short-task>` — `fix/`, `feat/`, `refactor/`, `chore/`.
- **Repo not on GitHub yet** (no `origin` remote): the project is in very active development. Work straight on `main`, but still split the work into small commits, one per logical change, with conventional-commit messages and no AI attribution. The branch, PR and merge rules below start once the repo is on GitHub.
- **One task = one branch = one PR.** Past ~300 changed lines, split it into several PRs. `size:XL` or `size:XXL` means split the PR, not "explain why it is large".
- **PR title is the squash commit subject:** conventional commit with a scope, enforced by `.github/workflows/pr-title.yml`.
  - Type: `feat` `fix` `refactor` `chore` `docs` `test` `ci` `perf` `revert`.
  - Scope (required): a crate — `agent` `proto` `server` `wgctl` — or `dist` `scripts` `deps` `github` `docker`. A new crate means adding it to the `scopes:` list in that workflow.
  - Subject: lowercase start, imperative, no trailing period.
  - The body describes this PR alone, following the PR template.
- **No AI attribution.** No `Assisted-by:` / `Co-Authored-By: <LLM>` trailers and no "Generated with …" lines. The PR body becomes the squash commit body, so the PR title workflow fails a PR that carries one.
- **Before opening:** `just check` green, then open the PR and report its URL.
- **Never merge locally.** Merging happens on GitHub, squash only.
