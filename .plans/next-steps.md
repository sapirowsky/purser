---
title: "Next Steps — pick up here"
status: "active"
updated: "2026-07-14"
one_line: "Where Purser stands and exactly what to do next."
---

# Next Steps — pick up here

## Where it stands (end of 2026-07-14)

- **Published:** `purser` 0.0.2 on crates.io (+ `purser-core`, `purser-vault`, `purser-store`).
  Repo: `github.com/sapirowsky/purser`, tagged `v0.0.2`. Code at `C:\Users\sapir\Desktop\purser`.
- **Works today (single machine):** encrypted vault + agent-blind execution —
  `import`, `secrets list/set`, `run`, `shell`, `agent`, `audit`. Values stay off disk,
  out of the parent env, out of the audit log. Verified end-to-end.
- **Not built yet:** device sync, `purser up` bootstrap, project manifest, MCP metadata tools.

## ▶ START HERE tomorrow: Week 2 — project manifest + `purser up`

Goal: one command reproduces a machine's projects. Single machine first (no sync yet).
The `projects` table already exists in the schema; this wires it up.

Build, in order:
1. `purser project add .` — register the current repo: detect git remote + branch +
   package manager (npm/pnpm/cargo/uv), link a secret profile. Writes a `projects` row.
2. `purser status` — list registered projects: which are cloned, which are missing,
   which have their env configured.
3. `purser up` — for each registered project:
   - clone from its git remote if the folder is missing,
   - run the dependency install (`npm/pnpm/cargo/uv`) to rehydrate deps,
   - make sure its profile's secrets are present (prompt/report if missing).
4. **Deliverable / gate:** wipe a projects folder, run `purser up`, get it all back —
   without touching a `.env` by hand.

Suggested workflow (same as today): delegate the implementation to Codex with a tight
brief, then review + build + test + verify + commit. Keep the value-blind rules intact.

## After `up`: `purser hook` — transparent use (no typing `purser`)

Depends on the manifest + `--profile auto` from Week 2. `purser hook` installs shell
aliases once per device so `bun run build`, `pnpm dev`, `claude` etc. run normally and
purser injects/withholds secrets underneath. **Must be a no-op outside purser projects**
(pass through to the raw tool; never error). Full design: `purser-hook-ux.md`.

## Then (later weeks, don't start until Week 2's gate passes)

- **Week 3:** device pairing + p2p replication (iroh) between two machines. Set a secret
  on macOS, `purser up` on Windows, it's there.
- **Week 4:** add WSL (keyring file fallback), cross-platform hardening, the MCP metadata
  tools for `agent` (`secret_exists`/`secret_list`/`secret_usage`).

## Known TODOs already in the code

- `purser-vault`: WSL/Linux-without-Secret-Service keyring fallback (encrypted key file).
- `purser-sync`: real iroh transport + pairing + last-writer-wins reconciliation (all stubs).
- `agent` command: currently sanitized launcher + audit only; MCP tools are Week 3.

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

Just say e.g. "implement Week 2 (`purser up`), delegate to Codex and review" — or point at
this file. Everything above is grounded in the current repo state, not a fresh plan.
