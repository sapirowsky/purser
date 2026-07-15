---
title: "Next Steps — pick up here"
status: "active"
updated: "2026-07-15"
one_line: "Where Purser stands and exactly what to do next."
---

# Next Steps — pick up here

## Where it stands (end of 2026-07-15)

- **Published:** `purser` 0.0.2 on crates.io (+ `purser-core`, `purser-vault`, `purser-store`).
  Repo: `github.com/sapirowsky/purser`, tagged `v0.0.2`. Code at `C:\Users\sapir\Desktop\purser`.
- **Works today (single machine):** encrypted vault + agent-blind execution —
  `import`, `secrets list/set`, `run`, `shell`, `agent`, `audit`. Values stay off disk,
  out of the parent env, out of the audit log. Verified end-to-end.
- **Week 2 built (branch `week2-manifest-up`, unmerged, unreleased):**
  `project add/remove`, `status`, `up [--dry-run]`, plus `hook` and `--profile auto`.
  Schema migration `002_project_paths` adds `projects.local_path`.
  Verified by running: wiped a project folder → `up` cloned it, checked out its branch,
  ran `npm install`. Hook proven in bash + PowerShell: dev tools see secrets, agents
  don't, outside purser it passes through even with purser off PATH entirely.
- **Not built yet:** device sync (Week 3), WSL keyring fallback + MCP metadata tools (Week 4).

## ▶ START HERE: pass Gate B yourself

Week 2's code is done, but **Gate B is a usage test, not a code test** — the plan says it
passes only when *you* stop doing the manual clone/env dance. Nobody can do that for you.

1. Merge `week2-manifest-up` into `main` (it's committed there, not merged).
2. Register your real projects: `purser project add <path> --profile <name>`.
3. Install the hook once: add `eval "$(purser hook bash)"` to your rc file
   (or `purser hook powershell | Out-String | Invoke-Expression` in `$PROFILE`).
4. Live on it for a few days. If `up` + `hook` are fiddlier than doing it by hand,
   **simplify before building sync** — that's the gate's whole point.

## Notes from the Week 2 build (worth knowing)

- **Windows `.cmd` shims.** `Command::new("npm")` cannot spawn on Windows: `CreateProcess`
  only appends `.exe`, and npm/pnpm/yarn are `.cmd` shims. Programs now resolve through
  PATH/PATHEXT. Anything new that spawns a tool must use `child_command`/`program_command`,
  not `Command::new` on a bare name.
- **`\\?\` verbatim paths.** `fs::canonicalize` always adds the prefix on Windows; it does
  not compare equal to `current_dir` output and git rejects it. `canonical_project_path`
  strips it. Sync (Week 3) will need its own answer for cross-machine path portability —
  the manifest stores absolute local paths, which differ per machine by design (seam 1:
  the ULID is identity, the path is only a projection).
- **`_in-project` costs ~32ms**, of which only ~5ms is SQLite — the rest is Windows process
  spawn, so there's little left to optimize without a resident daemon.

## Then (later weeks, don't start until Gate B actually passes)

- **Week 3:** device pairing + p2p replication (iroh) between two machines. Set a secret
  on macOS, `purser up` on Windows, it's there.
- **Week 4:** add WSL (keyring file fallback), cross-platform hardening, the MCP metadata
  tools for `agent` (`secret_exists`/`secret_list`/`secret_usage`).

## Known TODOs already in the code

- `purser-vault`: WSL/Linux-without-Secret-Service keyring fallback (encrypted key file).
- `purser-sync`: real iroh transport + pairing + last-writer-wins reconciliation (all stubs).
- `agent` command: currently sanitized launcher + audit only; MCP tools are Week 4.
- `up` reports a profile's *configured* secrets, but nothing declares which secrets a project
  actually NEEDS — so "missing" can only ever mean "registered but unconfigured". A
  `required secrets` list per project would make `up`'s env check meaningful.
- The hook wraps a fixed tool list (npm/pnpm/bun/yarn/node/vite/cargo/uv, claude/codex).
  Adding a tool means re-running `purser hook`; there is no per-project override yet.
- Only bash/zsh/powershell are generated — no fish, no nushell, no cmd.

## Small loose ends (optional, low effort)

- [ ] Buy a domain when ready — `purser.rs` (via Gandi/101domain) or `purser.sh` (Porkbun).
      Least urgent. `purser-rs.github.io` is the free stopgap. (see naming.md)
- [ ] Claim remaining crate names if wanted: publish `purser-sync/mcp/daemon` stubs at 0.0.2.
- [ ] Umbrella GitHub org: still deferred; `purser` stays on personal profile. (see naming.md)
- [ ] This `futureos` planning repo is local-only (unpushed) — push it somewhere if desired.
- [ ] Record the two design futures discussed today as named capabilities in the plan:
      loose-file (non-git) sync via "synced path sets", and the hosted/self-hosted central
      state server via the seam-3 transport trait. (Architecture already supports both.)

## How to resume with Claude

Just say e.g. "implement Week 3 (device pairing), delegate to Codex and review" — or point at
this file. Everything above is grounded in the current repo state, not a fresh plan.

One lesson from the Week 2 delegation, worth repeating: Codex's output passed its own
`build`/`test`/`clippy`/`fmt` clean and was still broken on Windows — `up` could not install
deps for any Node project. Its tests checked package-manager *detection* but never
*execution*. **Green checks are not verification; run the thing.** Every real bug that
session was found by executing the command, not by reading the diff or trusting the report.
