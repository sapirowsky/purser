---
title: "Purser v1 — One-Command Dev Sync"
version: "4.2"
status: "active"
created: "2026-07-14"
updated: "2026-07-15"
supersedes: "agent_capability_broker_v4.md (v4.0), devsync_v1_plan.md, objectos_agent_workspace_plan_v2.md"
scope_locked_by_owner:
  - "Sync scope: bootstrap + secrets. NO live working-tree sync. Git carries committed code."
  - "Transport: peer-to-peer between the owner's own devices. No hosted server."
  - "2026-07-15 — Gate C called EARLY: the agent-blind half is CUT. See 'Gate C, called early'."
one_line: "One command sets up any of my machines — clone every repo, rehydrate deps, and have my env already there — with secret values syncing peer-to-peer between my devices, encrypted at rest and on the wire."
---

# Purser v1 — One-Command Dev Sync

> **2026-07-15 — the agent-blind half is cut.** This document still describes it below,
> because the code exists and works. It is no longer a reason this project exists.
> Read "Gate C, called early" before acting on any section that mentions agents.

## The actual problem (owner's words)

> I have 3 systems on 2 machines: Windows, then WSL, then macOS. Setting up each one
> means manually cloning every repo, re-adding env variables, and now those variables
> sit in `.env` where any agent can read them. I want one command to sync my repos and
> env across devices, without exposing secrets to AI.

That is the whole spec. Purser is built for this person and this setup first. Because the
owner is the customer, "does it make my daily life across 3 systems easier?" is the only
success test that applies — market size is irrelevant.

## What it does

Two commands cover the entire pain:

```text
purser up                 # on any machine: reproduce my whole dev environment
  → clones every project from its git remote
  → rehydrates dependencies (npm/pnpm/cargo/uv install per project)
  → injects env from the encrypted vault — NO plaintext .env written to disk

purser agent -- claude    # run an agent that can work, but can't see secrets
  → agent launched with ZERO secret variables in its environment
  → values injected only into child processes the agent asks the broker to run
  → agent's model context and transcript never contain a credential
  → every use / injection / denied read is recorded as a receipt
```

Secrets and the project manifest sync **peer-to-peer** between the owner's devices —
encrypted on the wire, encrypted at rest. No server to run, nothing to pay for, nothing
hosted that could see the data.

## Scope, locked

Two forks were decided by the owner; the rest of the plan obeys them.

```text
SYNC SCOPE = bootstrap + secrets
  Sync: project manifest (repos + remotes + branch), env/secret ciphertext, lockfile refs.
  Do NOT sync: working trees, uncommitted edits, node_modules, target/, build output.
  Committed code travels through git, as it already does. The owner pushes WIP themselves.
  → This removes file watchers, three-way merge, and conflict objects entirely.
    The one part of DevSync that could corrupt a working tree is simply not built.

TRANSPORT = peer-to-peer between the owner's own devices
  Devices sync directly (QUIC + NAT hole-punching); a lightweight relay only assists
  connection setup, never sees plaintext.
  → This removes the hosted service, S3 storage, and DevSync's multi-recipient key
    hierarchy. One owner, a set of trusted devices, one shared vault key.
```

Explicitly out of v1 (earned later, each behind its own gate):

```text
- Live working-tree sync of uncommitted edits.        (owner deferred it; git covers commits)
- Any hosted/managed server or paid infra.
- Team sharing, multi-person grants, member rekeying.  (single owner only)
- E2EE per-recipient envelopes, recovery ceremonies.   (needed only for OTHER people's data)
- Object model, FUSE, semantic search, package graph.  (v2 plumbing — not needed for this)
- Hard OS-sandbox containment of the agent.            (v1 is value-blind + audited, not tamper-proof)
```

## What syncs, and what each machine does locally

```text
SYNCED (tiny — kilobytes, p2p):
  project manifest   name, git remote, default branch, package manager, env profile ref
  secret vault       encrypted secret values + versions (ciphertext only)
  ignore/rehydrate   per-project rehydrate hints (install command, post-clone steps)

LOCAL, never synced (rebuilt on each machine by `purser up`):
  the repos          cloned from their git remotes
  node_modules etc.  reinstalled from the synced lockfile — never copied between machines
  plaintext .env     never exists; env is injected in memory at run time
```

The owner's `node_modules` instinct, generalized: **you never move dependencies between
machines — you move the lockfile and reinstall.** Same for every build/cache directory.

## Fast-follow: AI harness history sync (v1.1, not core)

A real owner pain: reach Windows Claude/Codex history from macOS. This is the same sync
machinery as the manifest — a third synced record type, "synced path sets" — so it costs
little once the transport exists, but it stays OUT of the 4-week core.

```text
What it syncs (union, append-mostly, low conflict):
  Claude Code   ~/.claude/projects/<encoded-path>/*.jsonl, ~/.claude/history.jsonl,
                sessions/, file-history/
  Codex         ~/.codex/sessions/, archived_sessions/, session_index.jsonl, history.jsonl

Three rules this feature MUST follow:
  1. Reconcile by project ID, not folder name.  The harness keys history by ABSOLUTE PATH,
     so the same project is `C--Users-sapir-Desktop-futureos` on Windows and
     `-Users-sapir-Desktop-futureos` on macOS. Naive file sync makes duplicates; Purser
     maps both machine paths to one opaque project ID (SEAM 1) and unifies the timeline.
  2. JSONL first, live SQLite later.  Append-only transcripts/history are safe to union.
     A live DB with an open WAL (Codex `logs_2.sqlite`) must NOT be copied mid-write —
     defer it to a checkpoint/backup-API path.
  3. Never sync credentials.  Exclude `~/.claude/.credentials.json`, `~/.codex/auth.json`,
     and config/token files — device-bound and secret. History is encrypted end-to-end
     like every synced record and is NEVER exposed to the metadata-only MCP surface
     (transcripts can contain pasted tokens).
```

## Architecture

A small cross-platform Rust workspace. One resident process (the broker/sync daemon),
introduced only because injection and p2p sync genuinely need it.

```text
purser-core     vault, manifest, policy, audit, and sync types
purser-store    SQLite migrations + repositories (local, per device)
purser-vault    encryption at rest + OS keyring integration
purser-sync     peer-to-peer transport, device pairing, manifest/secret replication
purser-daemon   resident process: secret injection, MCP endpoint, audit, sync loop
purser-cli      up · import · secrets · run · shell · agent · audit · device
purser-mcp      metadata-only MCP tools spoken by the daemon
```

Local storage: one SQLite DB per device.

```text
projects          name, git_remote, branch, package_manager, profile_ref
secrets           name, group, profile, configured status   (NO value)
secret_versions   ciphertext, version, created_at           (value ciphertext only)
devices           this device + paired peers, public keys
sessions          an agent/human run: scope, started/ended
audit_events      session_id, kind, secret_ref, decision (used|injected|denied), ts
sync_state        per-peer replication cursor
```

## Sync + device model (deliberately minimal crypto)

Because every device belongs to one owner, the key story is simple — no per-recipient
envelopes, no membership rekeying.

```text
One vault key (symmetric, XChaCha20-Poly1305) encrypts all secret values at rest.
Each device holds a copy of the vault key in its OS secret store:
    macOS Keychain · Linux Secret Service · Windows Credential Manager.
  WSL note: WSL often has no Secret Service — fall back to an encrypted key file
  unlocked at daemon start. (This is the owner's real third system; handle it explicitly.)

Enrolling a new device (pairing):
  1. Existing device shows a one-time pairing code (short, human-typeable / QR).
  2. New device enters it; the two run an authenticated handshake (PAKE / Noise seeded
     by the code) over the p2p channel.
  3. The existing device sends the vault key over that authenticated channel.
  4. From then on both devices replicate the manifest + secret ciphertext directly.

Transport: QUIC with a Noise handshake (e.g. an iroh/libp2p-class Rust library).
  A relay may help two devices find each other behind NAT; it only forwards ciphertext.
Replication: last-writer-wins per secret version, with full version history kept —
  a bad edit is recoverable because old versions are never destroyed. (Secrets rarely
  collide across your own devices; keeping history makes the rare case safe.)
```

## Secret + agent-blind model, stated honestly

Guarantees:

```text
- Secret values are never written to the audit log, never returned by any MCP tool,
  never placed in the agent's own environment, and never written to disk as plaintext.
- Values are decrypted only in memory and injected only into a specific approved child
  process, then dropped.
- On import, the source .env is removed (with warnings until every plaintext copy is gone).
- Every use, injection, and denied request is recorded and attributable.
```

Not claimed (same honesty the prior docs kept):

```text
- v1 does NOT contain a hostile same-user process. An agent with shell access can read
  the environment of a child IT asked to launch, or the keyring if the OS has it unlocked.
  Hard containment needs OS sandboxing — a later rung.
- What v1 removes is the DEFAULT leak the owner named: plaintext .env on disk and secrets
  sitting in the agent's own environment, with no record. That default is the actual problem.
```

MCP tools exposed to agents (metadata only — no value path exists):

```text
secret_exists(profile, name) -> boolean
secret_list(profile)         -> names + configured status
secret_usage(name)           -> declared references in the project
```

## Commands

```bash
# environment
purser up                                  # bootstrap/refresh this machine from the manifest
purser project add .                        # register the current repo (remote, pm, profile)
purser status                               # what's cloned, what's stale, what's missing env

# secrets
purser import .env --profile local          # encrypt values, remove plaintext .env
purser secrets list --profile local         # names + configured status, never values
purser secrets set DATABASE_URL --profile local --group db

# run
purser run --profile local -- npm test      # human-launched, in-memory injection
purser shell --profile local                # subshell with env injected
purser agent -- claude                       # sanitized launch + metadata-only MCP

# devices + audit
purser device pair                          # show/enter pairing code to enroll a device
purser device list                          # my trusted devices
purser audit last                           # most recent session receipt
purser audit --denied                        # every denied secret read, ever
```

## Delivery sequence — ~4 weeks, each week useful on its own

```text
Week 1  Local vault + agent-blind run, single machine.
        SQLite schema, encrypt-at-rest via keyring, import/list/set, run/shell,
        sanitized `agent --`, and the audit log.
        Deliverable: on your main machine, run agents that can't see secrets, with receipts.
        → Already solves half your stated pain, on one box, before any sync exists.

Week 2  Manifest + `purser up`, single machine.
        Register projects (remote, branch, package manager, profile). `up` clones,
        rehydrates deps, injects env. Reproduce a machine from the manifest.
        Deliverable: wipe a projects folder, `purser up`, get it all back — no .env dance.

Week 3  Device pairing + p2p replication between machine A and B.
        Pairing handshake, vault-key transfer, manifest + secret ciphertext sync.
        Deliverable: set a secret on macOS, `purser up` on Windows, it's there.

Week 4  Third system (WSL) + hardening + the gate.
        WSL keyring fallback, cross-platform pass, audit tamper-check, honest-limits
        README. Run all 3 of your systems off Purser for a week.
        → Gate: do you stop doing the manual clone/env dance? If yes, it's real.
        REVISED 2026-07-15: the MCP metadata tools originally scheduled here are CUT.
        What remains is WSL + cross-platform hardening + the gate.
```

## Gate C, called early (2026-07-15)

Gate C said: *"Fail: find which half (sync / agent-blind secrets) you actually kept using,
and cut the other."* After running Week 1 + Week 2 + the hook end-to-end on Windows, the
owner called it in twenty minutes rather than four weeks:

> "i dont see myself using this keyvault to hide values from agents especially that it
> doesn't really hide it because agent is always one command away from showing it. i will
> use it just with purser import when we have syncing so i don't have to remember about
> setting up envs in all my devices"

**The critique is correct, and this document already conceded it** (see "Not claimed"):
`purser run -- node -e "console.log(process.env.X)"` prints the value. Value-blindness was
only ever *audited, not contained*. Containment is ladder rung 2, and nobody built it.

```text
CUT — do not build, do not invest further:
  - MCP metadata tools (secret_exists / secret_list / secret_usage).   Week 4 item. Dead.
  - Any further work on `purser agent --`.  It stays in the binary because it already works
    and costs nothing to keep, but it is no longer a reason this product exists.
  - The "invisible to AI agents" claim, in the one_line and in any README.
  - Gate C's second clause ("you let agents near real credentials"). Deleted below.

KEPT — and note WHY, because it is not the obvious reason:
  - The vault. Encryption at rest is the SYNC SUBSTRATE, not the agent feature. Secret
    values cannot replicate between devices without it. Cutting agent-blindness does not
    touch the vault.
  - import / secrets / run / shell / hook / up / manifest / audit. All still earn their keep.

CONSEQUENCE — the remaining product is one sentence:
  bootstrap a machine (`up`) + have my env already there, synced (Week 3).
  Week 3 is now the ONLY thing between here and done.
```

### Sync scope, narrowed again (2026-07-15)

Week 3 replicates **secrets only**. The project manifest stays device-local and is NOT synced.

```text
WHY: `projects.local_path` is an absolute path — `C:\Users\sapir\Desktop\purser` on Windows,
     `/Users/sapir/Desktop/purser` on macOS. Replicating those rows verbatim would push one
     machine's paths onto another. Solving that needs either a per-device projects root
     (forces a flat layout) or a device-local path table with git-remote binding (+1 table,
     +reconciliation, migration 003).

     None of that is needed for the owner's stated want: "so I don't have to remember about
     setting up envs in all my devices." Secrets carry NO paths, so replicating them alone
     dissolves the whole problem.

     Crucially, the hard part of Week 3 — pairing, iroh transport, vault-key exchange — is
     IDENTICAL either way. Manifest sync is a small delta to add later, behind the same
     seam-3 transport, once the transport is proven. Nothing is wasted by deferring it.

COST, accepted: on a new machine you still clone repos and `project add` them by hand, once
     per device. `up --write-env` then materializes the env. The clone-every-repo half of the
     original pain stays manual for now — revisit only if it actually bites.

SCHEMA: no change. `projects` simply never enters the synced set.
```

### The plaintext rule, deliberately relaxed

This plan guaranteed *"no plaintext .env is ever written."* That guarantee existed to keep
values away from agents. With that goal cut, the owner chose to trade it for ergonomics:

```text
`purser up --write-env`  materializes a real .env from the vault on a fresh machine.
  Opt-in, never default. Injection via `run`/`hook` remains the default path.
  Rationale: tools that PARSE .env directly (Prisma, Docker Compose) work with no hook,
  and no ~32ms-per-command wrapper tax.
  Safety rails that do NOT bend:
    - `.env` is added to .gitignore BEFORE the file is created.
    - An existing .env is NEVER overwritten (it may hold values never imported).
    - 0600 on Unix. Buffers zeroized. Values still never reach stdout or the audit log.
  The vault stays the source of truth; the .env is a per-machine PROJECTION of it
  (consistent with seam 1: identity is the ULID, the file is a projection).
```

## Gates — kill / pivot (deadlines, not vision)

```text
Gate A — end of week 1
  You run your own agent on a real project through `purser agent --` and the injection
  ergonomics beat plain dotenv. Fail: fix ergonomics before building sync.

Gate B — end of week 2
  You reproduce a machine's projects with one `purser up` and don't touch a .env by hand.
  Fail: the manifest/rehydrate step is more fiddly than doing it manually — simplify it.

Gate C — CALLED 2026-07-15, ahead of schedule. See "Gate C, called early" above.
  Outcome: the agent-blind half is cut; sync is the half that survives.
  The clause about letting agents near real credentials is DELETED — the owner does not
  want it and the guarantee was never strong enough to earn it.
  What remains to prove (Gate C'):
    All 3 systems run off Purser for one week. Pass: you no longer manually clone repos or
    re-add env when switching machines. Fail: sync is more fiddly than the manual dance —
    in which case the honest answer is that Purser is a local vault plus `up`, and that is
    a fine place to stop.
```

## Test plan and acceptance

```text
- Values never appear in: audit log, MCP responses, agent environment, sync logs.
  (DISK is no longer on this list — `up --write-env` is an owner-approved exception.
   Everything else still holds: a value reaching the audit log or a sync log is a bug.)
- Import encrypts values and removes plaintext .env (warns until it's gone).
- `up --write-env` writes .env ONLY where none exists, gitignores it BEFORE creating it,
  and round-trips through Purser's own parser without corrupting any value.
- run/shell inject only in memory; parent environment unchanged afterward.
- `agent --` starts a child with zero secret variables.   (kept, no longer a headline)
- `purser up` on a clean machine clones all repos, installs deps, and injects env.
- node_modules / target / build dirs are never transmitted between devices.
- Pairing transfers the vault key only over an authenticated channel; an unpaired device
  gets nothing.
- Secret versions are retained; a new value never destroys the old one.
- Identical behavior across macOS, Linux, Windows, and WSL (with key-file fallback).
- Audit log tampering is detectable (append-only + checksum chain).
```

Private-v1 success (revised 2026-07-15 — the agent clause is cut):

```text
- The owner runs all 3 systems off Purser daily for two weeks.
- The manual clone-and-env dance stops happening.          ← the ONLY test that matters now
- Zero incidents of a value reaching the audit log or a sync log.
```

## Assumptions

```text
- Name is `Purser` (see docs/notes/naming.md); protocols are name-independent.
- Target credentials are local/test/staging dev secrets. Production custody is out.
- One owner, multiple trusted devices, peer-to-peer. No server, no other people, in v1.
- Committed code is git's job; Purser bootstraps and enriches, never replaces git.
- macOS, Linux, Windows, and WSL are all in scope from day one (no FUSE = no platform tax).
- Live working-tree sync and hosted infra are deferred, each behind its own later gate.
```

## North star, and the three seams that keep it reachable

The owner's long-horizon direction: start as a personal tool, grow into an OSS tool other
devs rely on, and eventually charge for the layer giants can't easily copy. The candidate
big swings (see `docs/plans/archive/objectos_ambition_map_v3.md`) are **git-with-permissions**,
**dev-sync (Dropbox/R2)**, and **object-storage code that doesn't need a filesystem**.

The big picture does **not** add scope to v1. Its entire job is to pick three abstractions
now so those futures never require a rewrite. Each costs ~nothing today.

```text
SEAM 1 — Identity is opaque, never a path.        (keeps the object-storage future open)
  Projects and secrets get opaque permanent IDs. The manifest maps ID → remote/path as a
  PROJECTION, not identity. v1 cost: a ULID column. Payoff: the "a path is a projection"
  thesis — the whole no-filesystem/object future — stays reachable without building it now.

SEAM 2 — Permissions are capabilities over resources, not a secrets-only feature.
                                                   (keeps permissioned-git open)
  Model every grant as (subject, capability, resource_id, audited). In v1 the only
  resource type is a secret. Later the SAME shape covers files, commits, branches — which
  IS permissioned-git, delivered as private overlay objects attached to a STOCK git repo.
  Rule that never bends: wrap and enrich git; never build a GitHub-replacement forge.

SEAM 3 — Sync replicates opaque encrypted records behind a transport trait.
                                                   (keeps dev-sync / R2 open)
  purser-sync moves opaque (id, ciphertext, version) records; it must NOT know the word
  "secret." Transport is a trait: v1 = p2p QUIC. Later = add a blob backend (R2/S3) or a
  relay behind the same trait, no caller changes. This is also the MONETIZATION seam:
  the free OSS core is local + p2p; the paid layer is the hosted relay/blob store + team
  E2EE (ladder rung 4).
```

Explicitly NOT reached from here — traps the ambition map already ruled OUT, and that stands:

```text
- A new mobile platform.   Distribution/coordination fight; agent leverage doesn't help.
- A Slack replacement.      Network-effects consumer product; at most a data-model feature
                           of a future team layer, never a product we build.
```

Business framing, kept honest: aim to be the tool a handful of devs can't live without,
open-core, with hosting/team as the paid layer — NOT to beat GitHub/Dropbox head-on.
Giants fall to "indispensable to a niche, then expand," never to a frontal clone.

## The conditional ladder (what "later" means — keep it out of v1)

Each rung is earned only by the one below it still being used.

```text
1. Tool        the owner stops doing the manual dance across 3 systems      (Gates A-C)
2. Trust       OS-sandbox containment: agent access tamper-proof, not just audited
3. WIP         optional snapshot/pull of uncommitted changes (the deferred sync fork)
4. Others      IF anyone else ever wants it: THEN add per-recipient E2EE + a relay/host.
               DevSync's crypto was right — it just belongs here, not in v1.
5. Substrate   the default door your agents enter every project through
```

The destination the older docs described is still reachable. The door is just small:
one command that makes any of your machines feel like your machine, with secrets your
agents can use but never see. Build that; let it earn the rest.
