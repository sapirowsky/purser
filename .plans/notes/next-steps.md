---
title: "Next Steps — pick up here"
status: "active"
updated: "2026-07-20"
one_line: "Read-only peer Git fetch is complete; peer-first bootstrap is next."
---

# Next Steps — pick up here

## Where it stands (2026-07-20)

**Physical Windows-to-macOS pairing is proven, the device mesh is implemented, and read-only
peer-to-peer Git fetch now works.** Metadata and secrets synchronize between paired physical
devices. Device discovery and revocation bookkeeping are in place through migration 005.

The Git milestone uses the paired device identity and a dedicated `purser/git/1` ALPN:

```text
purser sync serve
purser project sync <PROJECT> --from <DEVICE>
```

`PROJECT` resolves by registered name or opaque ID. `DEVICE` resolves by exact label or public
key, with ambiguous, self, unknown, unpaired, and revoked devices rejected. The source project
is addressed only by opaque project ID; peers cannot supply a filesystem path.

The fetch uses Git's native upload-pack negotiation and streams the pack over authenticated iroh
QUIC. Imported refs are isolated under:

```text
refs/remotes/purser/<device>/<branch>
refs/purser/<device>/tags/<tag>
```

No local branch, `HEAD`, ordinary tag, index entry, or working-tree file is updated. Integration
tests cover initial and incremental fetch, tags, dirty-tree preservation, divergent local branches,
authorization failures, and operation without a hosted remote.

### Start here next

Implement **peer-first `purser up` bootstrap** using the read-only peer fetch that now exists.
Build outputs and dependencies remain local. Do not add push, automatic checkout during
`project sync`, or working-tree synchronization.

Metadata sync still sends the full state. `sync_state` cursors remain deliberately deferred until
the state is large enough to justify optimizing the already-correct exchange.

---

## Historical Week 3 snapshot (2026-07-16; superseded where noted)

The notes below preserve the original Week 3 handoff. Its claims that physical Mac testing,
device mesh, and revocation were still pending are no longer current; use the snapshot above.

**Week 3 is built. Sync works.** Set a secret or register a project on one device, sync,
and it is on the other. That was the whole point of the project.

- **Published:** `purser` 0.0.2 on crates.io (+ `purser-core`, `purser-vault`, `purser-store`).
  Repo: `github.com/sapirowsky/purser`, tagged `v0.0.2`. Code at `<repo-root>` (this checkout).
- **Branch `week2-manifest-up`** — unmerged, unreleased. The name is stale: it now carries all
  of Week 3 as well. Rename or merge when convenient; nothing depends on the name.

```text
Week 1  vault + agent-blind run          import, secrets, run, shell, agent, audit
Week 2  manifest + up                    project add/remove, status, up, hook, --profile auto
Week 3  device sync                      device pair, sync, projects-root      ← NEW
```

Week 3 commits, in order:

```text
38e5400  3a+3b  iroh transport, device identity, pairing + vault-key transfer
c47af28  3c     secret replication between paired devices
414b8ab         order sync conflicts by instant, not timestamp string
8d6681a  3d     project manifest replication + projects root
```

Schema is at **migration 003** (`003_manifest_sync`: `projects.updated_at` + `settings`).
It has been applied to the real Windows database; existing data survived intact.

## What Week 3 actually does

```text
purser device pair                 # on A: prints a one-time code, 10 min, single use
purser device pair --join          # on B: prompts for the code (hidden), receives the vault key
purser sync serve                  # on A: listen for paired peers
purser sync --peer <NODE_ID>       # on B: bidirectional exchange (secrets + manifest)
purser projects-root <PATH>        # per-device; where `up` clones projects it has never seen
purser device info | list          # this device's NodeId; known devices
purser device listen | connect     # 3a connectivity probe (unauthenticated, harmless)
```

Three separate ALPNs, deliberately: `purser/transport/1` (hello), `purser/pair/1`,
`purser/sync/1`. Only paired devices may sync — the server checks the peer's NodeId against
the `devices` table and refuses before building or sending any record.

## ⚠ The one thing that matters now: Gate C′

**Everything above has only ever run on ONE machine.** Every "second device" in testing was a
`PURSER_DEVICE` scope on this Windows box. That is real enough to prove the protocol, and it
is NOT the same as the Mac.

What the Mac introduces that has never been exercised:

```text
- NAT traversal between two real networks (all testing was one host, one relay hop).
- macOS Keychain instead of Windows Credential Manager (the `keyring` crate's other backend).
- A genuinely different filesystem layout — the whole reason local_path is not synced.
- Two clocks that can disagree (LWW trusts wall clocks; see limitations).
```

**Expect the first real bug in pairing across networks, not in the merge logic above.**

Gate C′ (from the plan): run all 3 systems off Purser for a week. Pass = you stop manually
cloning repos and re-adding env when switching machines. Fail = sync is fiddlier than the
manual dance, and the honest answer is that Purser is a local vault plus `up`.

## ▶ START HERE tomorrow

```text
1. Pair the Mac. Build on macOS, `purser device pair` on Windows, then `purser device pair
   --join` on the Mac and enter the code at the hidden prompt.
   THIS IS THE REAL TEST. If it works, everything else follows.
2. Set projects-root on the Mac, `purser sync --peer <windows-node-id>`, then `purser up`.
   The Mac should clone your projects into its own root at its own paths.
3. Then just use it for a week. That is Gate C′; there is nothing to build to pass it.
```

Done (2026-07-16), before pairing the Mac for real:

```text
- The pairing code is no longer a CLI argument. `purser device pair --join` reads it from a
  hidden prompt (or stdin when piped), so the code that grants the vault key never lands in
  shell history or the process list. Hosting stays `purser device pair` (no secret).
```

## Known limitations — real, not theoretical

```text
- LWW TRUSTS WALL CLOCKS. Two devices whose clocks disagree by more than the gap between two
  edits of the same secret can pick the wrong winner. Version history is what makes this
  recoverable — nothing is destroyed. The plan accepted this tradeoff knowingly.
- Timestamps are ordered by parsed instant (414b8ab), NOT by string. The database holds two
  formats because an early build wrote raw epoch seconds. Never compare created_at with `>`.
- The debug binary went 4.8M -> 33M when iroh was linked. Fine, but this is a "one binary per
  machine" tool, so know the cost. Release size unmeasured.
- iroh uses the n0 PUBLIC relay (`presets::N0`) for NAT setup. It only forwards ciphertext and
  cannot read anything, but it is third-party infrastructure. Self-hosting is a later choice.
- `device listen`/`connect` (3a) is UNAUTHENTICATED by design. It carries only a hello and
  says so loudly. Never let it carry anything else.
- Pairing REFUSES onto a device that already holds secrets — replacing its vault key would
  make them permanently unreadable. So pair a device BEFORE importing anything on it.
```

## Testing two devices on one machine

`PURSER_DEVICE=<name>` scopes **both** the keyring accounts and the SQLite database, so a
second identity can be exercised without a second box. Unset = the real device.

```text
DB:      %LOCALAPPDATA%\purser\devices\<name>\purser.db
Keyring: device-key:<name>.purser  /  vault-key:<name>.purser
```

Without it, every process here is the same device and pairing fails with iroh's
"Connecting to ourself is not supported". Cleanup after testing:

```powershell
# PowerShell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\purser\devices\<name>"
```

```text
:: cmd
rmdir /s /q "%LOCALAPPDATA%\purser\devices\<name>"

:: cmdkey is a cmd builtin; it also runs from PowerShell
cmdkey /delete:device-key:<name>.purser
cmdkey /delete:vault-key:<name>.purser
```

**NEVER delete the unscoped `vault-key.purser`** — that key decrypts every secret you own.

## Dead — do not build (Gate C, called 2026-07-15)

```text
- MCP metadata tools (secret_exists / secret_list / secret_usage). Cut. Not "later" — dead.
- Further work on `purser agent --`. It stays because it works and costs nothing to keep.
- The "invisible to AI agents" claim, anywhere.
```

## Remaining, in rough priority

```text
- Gate C′: three systems, one week. Nothing to build. ← the only thing that matters
- WSL keyring fallback (encrypted key file). WSL often has no Secret Service. Week 4's
  remaining real work, and the third of the owner's three systems.
- Pairing code via stdin rather than argv (see above).
- `sync_state` cursors. The table exists and is UNUSED — full exchange is correct at this
  size. Do not build this until the data is big enough to justify it.
- Rename the branch, or merge Weeks 2+3 to main and release.
```

## Known TODOs in the code

```text
- purser-vault: WSL/Linux-without-Secret-Service keyring fallback (encrypted key file).
- `up` reports a profile's *configured* secrets, but nothing declares which secrets a project
  actually NEEDS — so "missing" can only mean "registered but unconfigured". A per-project
  `required secrets` list would make `up`'s env check meaningful.
- The hook wraps a fixed tool list (npm/pnpm/bun/yarn/node/vite/cargo/uv, claude/codex).
  Adding a tool means re-running `purser hook`; no per-project override.
- Only bash/zsh/powershell hooks — no fish, nushell, cmd.
- `purser-sync` no longer has sync stubs; pairing and replication are real. The `Transport`
  trait is now async + Result and is RPITIT, so it is not dyn-compatible. Fine for now; a
  blob/relay backend swaps in via generics.
```

## Small loose ends (optional)

```text
- [ ] Buy a domain — `purser.rs` (Gandi/101domain) or `purser.sh` (Porkbun). `purser-rs.github.io`
      is the free stopgap. (see naming.md)
- [ ] Claim remaining crate names: publish `purser-sync/mcp/daemon` stubs at 0.0.2.
- [ ] Umbrella GitHub org: deferred; `purser` stays on the personal profile. (see naming.md)
- [ ] Record the two design futures as named capabilities in the plan: loose-file (non-git)
      sync via "synced path sets", and a hosted/self-hosted state server behind seam 3.
```

## How to resume with Claude

Point at this file. Everything above is grounded in the repo as it stands, not a fresh plan.

Two lessons worth repeating, both earned:

**Green checks are not verification; run the thing.** Every real bug in Week 3 was found by
executing the command, never by reading the diff or trusting a report. The 3b transport race
(a listener died serving a peer that hung up normally) passed every test and only appeared
when two processes actually talked. Codex could not compile in 3a/3b and could not run the
CLI in 3c/3d — it was honest about it, but it means the CLI verification is always yours.

**A passing negative test can pass for the wrong reason.** The first "unpaired peer is
refused" test passed because the rogue refused *itself* client-side and never dialed. The
server's authorization never ran. If a refusal test passes, check the *server* logged it.
