---
title: "purser hook — transparent, per-folder secret injection"
status: "decided (design)"
created: "2026-07-14"
relates_to: "docs/plans/purser_v4_plan.md, docs/notes/next-steps.md"
one_line: "Set up shell aliases once per device so devs run tools normally; the encrypted vault replaces .env; aliases are a no-op outside purser projects."
---

# purser hook — transparent, per-folder secret injection

## Decision

The daily UX goal is **"set it up once per device and forget."** The developer should NOT
type `purser ...` before every command.

- `purser hook` installs shell aliases/functions (bash/zsh/PowerShell) **once** per device.
- Then the dev runs tools **normally** — `bun run build`, `pnpm dev`, `vite`, `claude` — and
  purser transparently injects (or withholds) secrets underneath.
- The encrypted vault replaces the plaintext `.env`. The hook is the ergonomic layer on top:
  **private env becomes an addition configured via `purser hook`**, not a file on disk.

## Hard requirement: safe outside purser projects

The owner's constraint, and it is non-negotiable:

```text
- The aliases must be a NO-OP when the current folder is not a purser-managed project.
- Inside a purser project  → route the tool through purser (inject for dev tools,
                              blind for agents).
- NOT a purser project, or purser not installed
                           → run the raw tool UNCHANGED. Never error, never require purser.
- Preferred: aliases active only inside purser folders; if they must be defined globally,
  they must transparently pass through to the real tool everywhere else.
```

This means a teammate or a random repo is never affected, and the dev never has to think
about it — outside purser, `bun` is just `bun`.

## Two policies baked into the aliases

```text
dev tools (npm/pnpm/bun/vite/node/…) → purser run  --profile auto -- <tool>   (need secrets)
agents    (claude/codex/…)           → purser agent -- <tool>                 (blind to values)
```

The interactive shell stays clean — secrets go only into the child process, never into the
shell env — so convenience does not break the value-blind guarantee.

## Mechanism (for implementation later)

```text
purser hook bash|zsh|powershell   → prints shell code to add to the rc file (or eval).

Each wrapper does a fast membership check, e.g. (bash):
  bun() {
    if purser _in-project >/dev/null 2>&1; then
      purser run --profile auto -- bun "$@"
    else
      command bun "$@"          # transparent passthrough
    fi
  }

- `purser _in-project`  : exit 0 if cwd is inside a registered project. Must be FAST
                          (runs on every wrapped call). Detect via a marker (e.g. the
                          project's registered local path, or a `.purser` marker).
- `--profile auto`      : resolve the profile from the project manifest (git remote /
                          registered path). Falls back cleanly if ambiguous.
- Fallback chain        : purser missing OR not a project → exec the real tool.
```

## Considered and rejected: package.json scripts

Wrapping commands in `package.json` (`"dev": "purser run -- vite"`) works but is worse:
pollutes the repo, forces non-purser teammates to edit it, and covers only scripts (not
ad-hoc terminal commands). The hook is **per-device, not per-repo**, so repos stay standard.

## Depends on / ties to

```text
- Needs the project manifest + `--profile auto` project detection  → Week 2.
- The full "set up once, forget, secrets safe + synced" experience = hook (ergonomics)
  + device sync (Week 3+).
- Ambient direnv-style auto-load into the shell was rejected as the default: it would let
  agents read secrets too. Per-tool aliases keep the shell clean and encode policy per tool.
```
