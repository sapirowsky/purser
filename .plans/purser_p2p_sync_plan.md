# Purser P2P sync and performance plan

Date: 2026-07-20

## Objective

Make Purser a delta-based device synchronizer with peer-to-peer Git transport. Repository
synchronization should reuse Git's object negotiation and pack format instead of becoming a
generic file-transfer protocol.

Initially, "actual repository sync" means:

- Synchronize commits, branches, tags, and Git objects directly between paired devices.
- Bootstrap a missing repository from an online peer, using the hosted Git remote only as a
  fallback.
- Fetch updates into device-specific tracking refs.
- Fast-forward a clean working tree only when policy permits it.
- Never silently overwrite dirty or diverged work.
- Treat uncommitted working-tree synchronization as a later, separately opt-in feature.

## Phase 1: Establish performance measurements

Before changing the protocol, add repeatable benchmarks and instrumentation.

- Measure connection setup, discovery, direct versus relayed path, bytes sent, records
  examined, records transferred, encryption time, database-apply time, and peak memory.
- Add fixtures for:
  - Empty sync.
  - One changed secret among 100,000 versions.
  - Initial 1 GB repository transfer.
  - One new commit in a 1 GB repository.
  - Interrupted transfer at 50% and 95%.
  - Three and ten paired devices.
- Print direct/relay status in `purser sync --verbose`.

Acceptance targets:

- Unchanged metadata sync sends less than roughly 10 KB.
- One changed record performs work proportional to one record.
- Transfer memory remains bounded, initially under 64 MB.
- Incremental Git sync approaches ordinary `git fetch` performance.
- An interrupted transfer resends only missing data.

## Phase 2: Replace full-state replication with delta sync

The current implementation rebuilds and sends every secret version, project, and device
record for each peer. The existing `sync_state` cursor is not used.

Introduce an append-only change journal:

```text
sync_changes
  origin_device
  origin_sequence
  namespace
  record_id
  record_version
  operation       # upsert or tombstone
  payload_hash
  created_at

peer_cursors
  peer_device
  origin_device
  acknowledged_sequence
```

Each device owns a monotonically increasing sequence. Because changes can be gossiped through
other devices, cursors must be tracked per originating device rather than as one global number.

The exchange becomes:

1. Authenticate the paired device.
2. Exchange protocol capabilities and cursor vectors.
3. Determine missing change ranges.
4. Stream only missing changes.
5. Apply them in bounded database transactions.
6. Send an explicit durable acknowledgement.
7. Advance cursors only after the transaction commits.

Requirements:

- Applying a change must be idempotent.
- Tombstones must participate in the journal.
- A failed exchange must never advance a cursor.
- Keep journal entries until every active device acknowledges them.
- Introduce snapshot epochs later for safe journal compaction.

This is the single largest performance improvement.

## Phase 3: Redesign the transport for streaming and resumption

The current receiver accumulates the complete exchange in a `Vec<Record>`. Replace that with a
framed streaming protocol.

Use separate QUIC streams for:

- Control messages and cursor negotiation.
- Metadata changes.
- Repository pack data.
- Content chunks and acknowledgements.

Implementation changes:

- Apply incoming metadata incrementally instead of buffering the entire exchange.
- Set both per-record and total-in-flight byte limits.
- Use explicit batch IDs and durable application acknowledgements.
- Checkpoint large transfers using content hashes.
- Resume from the last verified chunk.
- Use BLAKE3 for payload and chunk integrity.
- Reuse established connections when the daemon is running.
- Synchronize several peers concurrently with a small limit, such as three.
- Serialize SQLite writes as needed while networking continues concurrently.

Compression policy:

- Do not compress individual secret values.
- Optionally compress ordinary metadata batches with zstd.
- Do not recompress Git packs; Git already performs delta compression.

## Phase 4: Add a peer-to-peer Git protocol

Create a dedicated crate such as:

```text
crates/purser-repo-sync
```

Do not implement Git object storage or delta compression. Use the installed Git executable,
which Purser already depends on operationally.

The protocol should exchange:

- Project ID.
- Repository object format.
- HEAD and symbolic branch.
- Branch and tag refs.
- Shallow-repository information.
- Git capabilities.
- Source-device identity.

Then run constrained Git plumbing over authenticated QUIC:

- Sender side: `git upload-pack`.
- Receiver side: Git fetch negotiation and pack ingestion.
- Longer term, expose a `git-remote-purser` remote helper so ordinary Git commands can address
  a paired device.

Example remote representation:

```text
purser::<project-id>/<device-id>
```

Store peer refs without mutating local branches:

```text
refs/remotes/purser/<device>/<branch>
```

This provides Git-native object negotiation: if the receiver already has nearly all of the
repository, only the missing objects and deltas travel.

## Phase 5: Define safe repository reconciliation

Repository synchronization must not automatically replace the working tree.

For each branch:

- Same commit: no action.
- Remote is an ancestor of local: local is ahead; retain and advertise it.
- Local is an ancestor of remote: report that a fast-forward is available.
- Histories diverge: retain both refs and report a conflict.
- Dirty working tree: fetch objects and refs, but do not update the checked-out branch.
- Force-pushed or deleted remote ref: preserve the old ref until the user approves removal.

Suggested commands:

```text
purser project sync app                 # exchange objects and refs safely
purser project sync app --apply         # fast-forward clean branches
purser project sync app --from laptop   # select a source device
purser project status app               # ahead/behind/diverged/dirty
```

Never automatically:

- Force-reset branches.
- Merge divergent histories.
- Create commits.
- Discard untracked or modified files.
- Push changes to a hosted remote.

## Phase 6: Bootstrap repositories from peers

Change `purser up` source selection to:

1. Adopt an existing matching local repository.
2. Find an online paired device advertising the project.
3. Fetch Git objects and refs from that peer.
4. Check out the configured branch.
5. Fall back to the configured hosted Git remote.
6. Report a clear error if no source is reachable.

That makes the Git remote optional instead of the only bootstrap source.

After a repository exists, `purser up` should:

- Perform delta metadata sync.
- Fetch peer repository changes.
- Apply only safe fast-forwards according to policy.
- Rehydrate dependencies only when lockfiles or dependency manifests changed.
- Continue handling one failed project without blocking the others.

## Phase 7: Add optional working-tree sync

Do this only after committed Git synchronization is reliable. Uncommitted state has more
dangerous conflict behavior.

Create snapshots containing:

- Relative path.
- Content hash.
- Executable bit and limited portable metadata.
- Base snapshot ID.
- Tombstones for deleted files.
- Content-addressed chunks.

Default exclusions:

- `.git/`.
- `.env` and known secret files.
- Ignored files from `.gitignore`.
- Dependency and build directories.
- Sockets, device files, and unsafe symlinks.

Use three-way reconciliation against the last common snapshot:

- Changed on one device: apply safely.
- Changed identically on both: accept.
- Changed differently: retain both versions and report a conflict.
- Never overwrite a locally modified file without an unchanged common base.

Expose this explicitly:

```text
purser project sync app --worktree
purser project conflicts app
```

It should remain opt-in until its conflict and secret-exclusion model is thoroughly tested.

## Phase 8: Harden security and compatibility

- Introduce protocol capability negotiation before replacing `purser/sync/1`.
- Keep metadata, Git, pairing, and worktree operations on separate ALPNs or strongly separated
  protocol channels.
- Authorize every project by opaque project ID.
- Validate Git ref names and reject dangerous namespaces.
- Constrain spawned Git processes to the registered repository.
- Prevent path traversal, symlink escapes, and writes outside the project.
- Rate-limit peers and bound advertised refs, records, chunks, and total bytes.
- Stage packs and worktree files temporarily, verify hashes, then commit atomically.
- Add vault-key rotation before claiming device revocation provides full security.

## Suggested delivery order

1. Benchmarks and sync instrumentation.
2. Change journal and per-origin cursors.
3. Streaming application acknowledgements.
4. Concurrent peer synchronization.
5. P2P Git ref advertisement and `upload-pack`.
6. Peer bootstrap for missing repositories.
7. Safe fetch and fast-forward policies.
8. Resume/checkpoint support.
9. Daemon connection reuse.
10. Optional uncommitted working-tree synchronization.

The first six milestones deliver the central outcome: Purser synchronizes only changed metadata
and exchanges actual Git history directly between devices while retaining the hosted Git remote
as a fallback.
