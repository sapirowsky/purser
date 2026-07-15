---
title: "Purser v1.1 — Device Mesh + Project Relocation"
version: "1.1"
status: "proposed"
created: "2026-07-16"
builds_on: "purser_v4_plan.md (v1 — One-Command Dev Sync)"
one_line: "Devices introduce each other so no machine is a hub, and a project can move on disk without orphaning its agent history."
---

# Purser v1.1 — Device Mesh + Project Relocation

Two features. They share nothing technically; they are one plan because they are the two
things the owner asked for after Week 3 landed, and both are about **identity surviving a
change of location** — which is seam 1 doing its job.

> Prerequisite: Week 3 (`38e5400`, `c47af28`, `414b8ab`, `8d6681a`, `f167bd5`) is built.
> Sync works between paired devices. **None of it has run on a second physical machine yet.**
> Gate C′ still outranks everything here. If pairing the Mac reveals something ugly, fix
> that first and come back.

---

# Part 1 — Device mesh (gossip the device list)

## The problem, in the owner's words

> "it would be good that single pc isnt host when my windows is off but my two others
> laptops are on they should sync between them"

## Why it does not work today

There is no hub *by design* — any device can serve, any can dial. But **pairing is pairwise**,
and the device list never travels. Pair each laptop to the Windows box and you get:

```text
Windows : knows Mac, knows laptop
Mac     : knows Windows                 ← never learns the laptop exists
laptop  : knows Windows                 ← never learns the Mac exists
```

Windows is not privileged. It is just the only device anyone was ever introduced to. With it
asleep, `purser sync` on the Mac has exactly one peer to try, and it is unreachable.

Working around this by hand means pairing every machine to every other machine: n(n−1)/2
codes, re-done whenever a device joins. That is the manual dance Purser exists to kill.

## The fix

**Replicate the `devices` table as a third record type**, alongside secrets (3c) and projects
(3d). When the Mac syncs with Windows it learns the laptop's public key and label; next time
both laptops are awake, they can dial each other directly. The mesh forms itself.

```text
Payload:  {device_id (ULID), label, public_key, paired_at}
Excluded: is_self  — that is this device's opinion about itself, exactly like local_path
                     is this device's opinion about where a project lives (3d's rule).
```

Follow `project_sync.rs` closely; it is the same shape.

```text
- Reconcile by public_key, NOT by ULID. The key IS the identity here — two devices may have
  minted different ULID rows for the same peer, because each generated its own row at pair
  time. On conflict, keep the earliest paired_at and the local label.
- Never let a gossiped row become is_self. `upsert_self_device` already guards the self row;
  the store has `CannotPairSelf` for exactly this.
- A device must ignore a gossiped record describing ITSELF (it will see its own key come
  back from every peer).
```

## The trust question, answered

Gossip means: any paired device learns about every other paired device. **This adds no trust
boundary.** Every paired device already holds the same vault key — that is what pairing
transfers. They are equally trusted by construction, and a device that could be told a lie
about a peer could already decrypt everything. One owner, one vault key, n devices.

What it DOES mean: **there is no per-device revocation**, and gossip makes that sharper. Today
`DELETE FROM devices` un-pairs a peer locally; with gossip, the next sync re-introduces it.

```text
DECIDE BEFORE BUILDING: revocation.
  Option A (v1.1): a `revoked` tombstone column that also replicates, so a revocation
    spreads instead of being undone. Cheap. Does NOT reclaim the vault key — a revoked
    device still holds it, so this is bookkeeping, not security.
  Option B (later): real revocation = rotating the vault key + re-encrypting every secret
    and re-pairing every surviving device. That is a real ceremony and belongs with the
    "Others" rung of the ladder, not here.
  Recommendation: A, and say plainly in the README that it is bookkeeping. Do not imply
    a revoked laptop cannot read secrets it already synced. It can.
```

## Cost

Small. A fourth record type in the existing exchange, one payload codec, one reconcile
function, reusing the sync ALPN, authorization, and encryption already proven in 3c/3d.

## Gate

Pair B→A and C→A only. Sync. Turn A off. B and C must find each other and sync.
**That is the whole test, and it cannot be faked with `PURSER_DEVICE` alone** — well, it can
(three scopes, one box), but it does not prove NAT traversal between two real networks.

---

# Part 2 — `purser project move`

## The problem, in the owner's words

> "copying projects on 'this' pc so i can move a project with all codex/claude histories to
> different place"

Move `Desktop\museo` to `Desktop\work\museo` and the code moves fine — git does not care.
The **agent history does not follow**, because both harnesses bind history to the project's
absolute path. Claude opens the new folder with no memory of the work; Codex cannot resume.

This is the same root cause the v1 plan already identified for cross-machine history sync
("Reconcile by project ID, not folder name"). Local relocation is that problem with one
machine, which makes it the cheaper place to solve it first.

## What is actually on disk (verified 2026-07-16, this machine)

**The two harnesses are opposites.** This is the central fact of the design.

```text
CLAUDE — path is the INDEX KEY (a directory name)
  ~/.claude/projects/C--Users-sapir-Desktop-purser/
      <session-uuid>.jsonl        transcripts (the path appears ~148x inside one file)
      <session-uuid>/             per-session dir
      memory/                     project memory
  ~/.claude/history.jsonl         GLOBAL, one line per command:
                                  {"display":"...","project":"C:\\Users\\sapir\\Desktop\\museo",...}

CODEX — path is a FIELD INSIDE date-partitioned files
  ~/.codex/sessions/2026/02/06/rollout-<ts>-<uuid>.jsonl
      first line: {"type":"session_meta","payload":{"cwd":"c:\\Users\\sapir\\Desktop\\museo",...}}
  ~/.codex/history.jsonl, session_index.jsonl
  ~/.codex/logs_2.sqlite (+ -wal, -shm)   LIVE DB — never touch mid-write
```

So Claude needs a **directory rename**; Codex needs a **field rewrite across scattered files**.
There is no single mechanism.

## Three findings that constrain the design

### 1. The Claude encoding is AMBIGUOUS — never decode it

`C--Users-sapir-Desktop-museo-copy` could mean `Desktop\museo-copy` **or** `Desktop\museo\copy`.
Separators become `-`, and a literal `-` in a folder name is left alone, so the mapping is
lossy. Both spellings were observed in this machine's `~/.claude/projects`.

```text
RULE: map FORWARD only (path -> key). Never parse a key back into a path.
      Purser knows the real path — it is in `projects.local_path`. Use it.
```

### 2. Case is not consistent

Observed side by side: `C--Users-sapir-Desktop-museo-copy` and `c--Users-sapir-Desktop-museo`.
Codex writes `"cwd":"c:\\Users\\..."` with a lowercase drive letter. Windows paths are
case-insensitive; these keys are byte strings.

```text
RULE: match paths case-insensitively on Windows; preserve whatever case is found when
      writing. Do not "normalize" a drive letter and orphan a directory that used the other.
```

### 3. A live session is being appended to RIGHT NOW

`~/.claude/projects/C--Users-sapir-Desktop-purser/5af05d7c-....jsonl` was mtime-current while
this plan was written — that is this conversation. Codex holds `logs_2.sqlite` open with a WAL.

```text
RULE: REFUSE to move a project with a live session. Detect it (recent mtime, lock, running
      process) and stop with a clear message. Rewriting a file the harness is appending to
      corrupts the transcript, and the owner loses history the command exists to preserve.
```

## The design question that must be answered first

Moving history means changing what the record says. Be exact about what may change:

```text
REWRITE (index keys — what the harness uses to FIND history):
  - the ~/.claude/projects/<key> directory name
  - ~/.claude/history.jsonl        "project" field, only on lines matching the old path
  - ~/.codex/sessions/**           session_meta.payload.cwd, only where it matches
                                   (rewrite the ONE meta line; stream the rest byte-for-byte)

DO NOT REWRITE (the record of what happened):
  - transcript bodies. The ~148 path mentions inside a Claude transcript are history: that
    command really did run at that path. Rewriting them fabricates a past that did not
    happen, and the owner would have no way to know. Leave them. Resume still works —
    the harness finds the session by key, not by grepping the body.

NEVER TOUCH:
  - ~/.claude/.credentials.json, ~/.codex/auth.json — device-bound secrets, and the v1 plan
    already forbids Purser going near them.
  - ~/.codex/logs_2.sqlite and any open WAL. A live DB is not a file you copy.
```

## Safety rails (this command edits the owner's irreplaceable history)

```text
- BACK UP FIRST, unconditionally. Copy the Claude project dir and every touched Codex
  session to a timestamped folder before writing a byte. Print where it went. This is not
  optional and not behind a flag: transcripts are unversioned and irreplaceable.
- --dry-run must be the thing you reach for first, and must list every file it would touch.
- Refuse on a live session (finding 3).
- Refuse if the destination exists and is non-empty (mirror `up`'s adopt/refuse rule).
- Move the working tree with `git mv`-grade care: it is just a directory move, but verify
  the repo still resolves afterward (`git -C <new> status`).
- Update `projects.local_path` for THIS device only. The path is not synced (3d) — moving a
  project on Windows must not touch where the Mac keeps it. This is exactly why local_path
  is device-local, and it is a nice proof that the 3d decision was right.
- Rewrite atomically: temp file + rename, per file. A half-rewritten history.jsonl is worse
  than no move at all.
- If ANY step fails, say what was done and what was not, and point at the backup. Do not
  attempt a clever rollback of a half-finished multi-harness move.
```

## Command shape

```bash
purser project move <FROM> <TO>          # move dir, carry history, update the manifest
purser project move <FROM> <TO> --dry-run
purser project move <FROM> <TO> --no-history   # just move + update manifest
```

The owner said "copying" as well as "moving". Decide:

```text
  move  — the common case, and what the words above describe. Do this one.
  copy  — duplicates the tree AND the history under a second key. Tempting, but two
          projects then share one history's past, and no harness expects that. The observed
          `museo-copy` suggests copies do happen. RECOMMEND: ship `move` first; only add
          `copy` if the owner actually wants the history duplicated rather than orphaned.
```

## Gate

Move a real, unimportant project. Open Claude in the new location: history is there, `/resume`
lists old sessions. Open Codex: `codex resume` finds them. Then check the old path is gone
from both, and that `purser status` and the hook still resolve the project.

---

# Sequence

```text
0.  Gate C′ first. Pair the Mac. Nothing here matters if the transport is broken in the
    real world. (see notes/next-steps.md)
1.  Device mesh. Small, reuses everything, and directly answers a stated want.
    Decide revocation (Option A) before writing code.
2.  project move. Bigger and riskier — it edits irreplaceable history. Back up first,
    dry-run first, refuse on live sessions.
```

# Explicitly NOT in v1.1

```text
- Cross-machine harness history sync. The v1 plan's "synced path sets" fast-follow. Part 2
  builds the path-mapping half it needs, but shipping history over the wire adds transcript
  size (megabytes vs the kilobytes sync moves today) and a real leak risk: transcripts can
  contain pasted tokens. It must never touch the metadata-only surface. Separate decision.
- Real revocation (vault-key rotation + re-encryption). Ladder rung 4.
- Any hosted relay. Still out; still the monetization seam when it arrives.
- Copying a live Codex SQLite DB. Needs a checkpoint/backup API, not a file copy.
```
