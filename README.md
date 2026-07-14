# purser 🦀

**One command sets up any of your machines — clone every repo, rehydrate deps, inject env —
and secret values sync peer-to-peer between your devices while staying invisible to AI agents.**

Built with Rust. Rust good.

> Status: **early scaffold.** Nothing is implemented yet — this is the workspace skeleton with
> the architecture's two load-bearing seams baked into the schema. 

## What it will do

```
purser up                 # reproduce this machine: clone repos, install deps, inject env
purser agent -- claude    # run an agent that can work but can't see secret values
purser run -- npm test    # run with secrets injected in memory only
purser audit last         # receipt: what was used / injected / denied
purser device pair        # enroll another of your own devices (peer-to-peer)
```

No plaintext `.env` on disk. No hosted server. Committed code still travels through git.

## Workspace

```
crates/
  purser         # the `purser` binary/CLI (holds the crates.io name)
  purser-core    # opaque ULID identity (seam 1) + generic capabilities (seam 2)
  purser-store   # SQLite migrations + repositories
  purser-vault   # encryption at rest + OS keyring
  purser-sync    # p2p transport (trait), device pairing, replication (seam 3)
  purser-daemon  # resident process: injection, MCP endpoint, audit, sync loop
  purser-mcp     # metadata-only MCP tools (no value path exists)
```

## The three seams (why the schema looks the way it does)

1. **Opaque identity** — projects/secrets are ULIDs; paths and git remotes are *projections*,
   never identity. Keeps the object-storage future reachable.
2. **Capabilities over generic resources** — `grants(subject, capability, resource_type,
   resource_id)`. v1 only sets `resource_type = 'secret'`; the shape already fits
   files/commits/branches. Keeps the permissioned-git future reachable.
3. **Sync moves opaque encrypted records behind a transport trait** — v1 is p2p QUIC; a relay
   or blob backend swaps in later with no caller changes. Also the monetization seam.

## Build

```
cargo build
cargo run -p purser -- --version
```

## License

MIT
