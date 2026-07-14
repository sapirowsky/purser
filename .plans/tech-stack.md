---
title: "Tech Stack — Purser v1"
status: "suggestion"
created: "2026-07-14"
relates_to: "docs/plans/purser_v4_plan.md"
one_line: "Language and crate choices for building Purser, with the rationale and the one real alternative."
---

# Tech Stack — Purser v1

Working notes / suggestions. Not binding — the plan is binding; this records *how* we'd
build it and why.

## Language: Rust

Chosen. It's a strong fit for this specific tool, not just a default:

```text
- Single static binary per platform, no runtime to install.
  → Directly solves the "3 systems, painful setup" pain: one binary onto
    Windows, WSL, and macOS and it runs.
- The p2p primitive is Rust-native: `iroh` (QUIC + NAT hole-punching) is
  best-in-class and is exactly seam 3's transport.
- It's a secrets tool → memory control matters. `zeroize` scrubs credential
  buffers; no GC quietly copying secret bytes around.
- Matches the long horizon (object store, permission engine, no-filesystem
  code) — all systems-level work where Rust is the natural home, so v1 never
  needs a language switch to reach the big picture.
```

### The one honest tradeoff

Rust is slower to author than Go (async + lifetimes) and v1 is a solo 4-week sprint. If
velocity becomes the bottleneck, **Go** is the only credible alternative — also
single-binary, also cross-platform, proven at serious p2p (Tailscale). What you'd give up:
precise secret zeroization and the `iroh`-quality p2p story. Verdict: stay on Rust; the
ambition is systems-level and four planning docs already assume it. Revisit only if the
drag is real.

## Crate stack, per component

| Piece | Crate | Notes |
|---|---|---|
| CLI | `clap` | derive API for the `purser` subcommands |
| Async runtime | `tokio` | needed by iroh + the daemon loop |
| Local store | `rusqlite` (bundled) | one SQLite DB per device |
| OS keyring | `keyring` | Keychain / Secret Service / Win Cred Mgr |
| WSL keyring fallback | encrypted key file | WSL often lacks Secret Service; unlock at daemon start |
| Crypto | RustCrypto `chacha20poly1305` + `x25519-dalek` | or `age` for a batteries-included envelope |
| Secret scrubbing | `zeroize` | zero credential buffers after injection |
| p2p transport | `iroh` | QUIC + hole-punching; seam 3 |
| Device pairing | PAKE / Noise handshake | seed from the one-time pairing code |
| MCP server | `rmcp` (official Rust SDK) | or a small JSON-RPC-over-stdio server |
| Process / env injection | std `Command` + `std::env` | in-memory only; never write plaintext |
| File watching (later) | `notify` | not core v1; harness-history / future sync |
| IDs | `ulid` | opaque permanent IDs — seam 1, from migration one |

## Workspace layout (matches the plan)

```text
purser/
├── Cargo.toml                # workspace
└── crates/
    ├── purser-core/         # vault, manifest, policy, audit, sync types
    ├── purser-store/        # SQLite migrations + repositories
    ├── purser-vault/        # encryption at rest + keyring
    ├── purser-sync/         # p2p transport (trait), pairing, replication
    ├── purser-daemon/       # resident process: injection, MCP, audit, sync loop
    ├── purser-cli/          # up · import · secrets · run · shell · agent · audit · device
    └── purser-mcp/          # metadata-only MCP tools
```

## Two seams to bake into the first migration

Cheap now, expensive to retrofit — put them in schema v1:

```text
1. Opaque identity.  projects.id and secrets.id are ULIDs. Paths/remotes are columns
   that PROJECT off the id, never the primary key. (Seam 1 — keeps object-storage future.)
2. Generic capability grant.  grants(subject, capability, resource_type, resource_id,
   audited). v1 only ever sets resource_type = 'secret', but the shape already fits
   files/commits/branches. (Seam 2 — keeps permissioned-git future.)
```

## Open questions to resolve while building

```text
- iroh relay: use the public relay for NAT setup, or self-host one? (public is fine for v1)
- age vs raw RustCrypto for the vault envelope? (age = less code, less control)
- MCP transport: stdio (simplest, matches how agents launch tools) vs a local socket?
- Pairing UX: numeric code vs QR — which is less annoying across your 3 systems?
```
