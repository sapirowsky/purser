//! Purser vault: encryption at rest + OS keyring.
//!
//! One symmetric vault key (XChaCha20-Poly1305) encrypts every secret value. The key lives
//! in the OS secret store via the `keyring` crate (macOS Keychain / Linux Secret Service /
//! Windows Credential Manager). WSL often lacks Secret Service — fall back to an encrypted
//! key file unlocked at daemon start.
//!
//! Invariant this crate enforces: values are decrypted only in memory, used, then zeroized.
//! Nothing here ever writes a plaintext value to disk, a log, or the MCP surface.

// TODO: VaultKey (from keyring / WSL key-file fallback), encrypt/decrypt, zeroize-on-drop.
