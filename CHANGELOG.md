# Changelog

All notable changes to Purser are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-16

First sync-capable release: pair your devices and your secrets and project manifest
replicate peer-to-peer, encrypted on the wire and at rest. `cargo install purser` now
yields the whole bootstrap-a-machine flow.

### Added

- **Device sync (peer-to-peer, no server).**
  - `purser device pair` shows a one-time enrollment code; `purser device pair --join`
    enrolls this device and receives the vault key over an authenticated channel.
  - `purser sync` (and `purser sync serve`) replicate encrypted secret values/versions
    and the project manifest between paired devices over iroh (QUIC), using the public
    n0 relay only for NAT traversal — it forwards ciphertext and can read nothing.
  - `purser projects-root <PATH>` sets, per device, where `up` clones projects it has
    never seen. `purser device info` / `purser device list` report identity and peers.
  - Last-writer-wins per record with full version history retained; conflicts are ordered
    by parsed instant with a deterministic tie-breaker so peers converge.
- **Machine bootstrap.** `purser up` clones every registered project, rehydrates
  dependencies, and injects env; `up` syncs from paired devices first. `purser project
  add` / `remove`, `purser status`.
- **Transparent injection.** `purser hook` installs per-project shell injection.
- **Opt-in dotenv.** `purser up --write-env` materializes a real `.env` from the vault
  (gitignored before creation, never overwrites, `0600` on Unix).

### Changed

- The "agent-blind / invisible to AI agents" framing was dropped (Gate C, 2026-07-15):
  value-blindness was only ever audited, not contained. `purser agent --` and the audit
  log remain, but are no longer a headline. The planned metadata-only MCP tools
  (`secret_exists` / `secret_list` / `secret_usage`) were cut and never built.
- Pairing codes are no longer accepted as a CLI argument (they granted the vault key and
  lingered in shell history / the process list). `--join` reads the code from a hidden
  prompt, or from stdin when piped.

### Security / hardening

- Compile the macOS Keychain backend (`apple-native`), not just Windows — without it a
  Mac silently fell back to an in-memory keystore and pairing broke.
- Reject unsafe `PURSER_DEVICE` scopes (path separators, drive letters, `.`/`..`) before
  they are joined into a path or keyring account.
- Device invariants are schema-enforced (migration `004`): one row per public key and a
  single self row, with the migration reconciling any historical duplicates first.
- `up --write-env` is failure-atomic: a hardened temp file is hard-linked into place
  (never overwriting), audited before commit, and cleaned up on every path.
- Bound the peer acknowledgement waits so an unresponsive peer cannot stall the sender.
- Validate stored timestamps per-month with leap years and bound the year, so a crafted
  value cannot overflow the date math.
- `up`'s pre-sync step is fully best-effort — a missing identity, an unbuildable runtime,
  or an unreachable peer degrades to local state instead of aborting.

## [0.0.2] - 2026-07-14

Local encrypted secret vault with agent-blind execution, single machine. First release of
the `purser-core`, `purser-store`, and `purser-vault` crates alongside the `purser` binary.

### Added

- Encrypt-at-rest vault (XChaCha20-Poly1305) keyed by one OS-keyring vault key.
- `purser import` (encrypts a `.env`, removes the plaintext), `purser secrets list` / `set`.
- `purser run` / `purser shell` inject secrets in memory; `purser agent --` launches a
  child with zero secret variables; `purser audit` exposes the append-only receipt log.
- SQLite store with migrations, and the opaque-identity (seam 1) and capability (seam 2)
  core types.

## [0.0.1] - 2026-07-14

Initial crates.io publish reserving the `purser` name; Cargo workspace scaffold.

[Unreleased]: https://github.com/sapirowsky/purser/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sapirowsky/purser/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/sapirowsky/purser/releases/tag/v0.0.2
[0.0.1]: https://crates.io/crates/purser/0.0.1
