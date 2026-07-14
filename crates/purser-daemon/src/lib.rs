//! Purser daemon: the single resident process.
//!
//! Responsibilities:
//!   * decrypt secret values in memory and inject them into approved child processes
//!     (human- or agent-launched), then zeroize — never into the agent's own environment;
//!   * speak the metadata-only MCP surface to agents;
//!   * append audit events (use / injection / denial) with the checksum chain;
//!   * run the p2p sync loop that replicates manifest + secret ciphertext between devices.

// TODO: process supervision, injection broker, MCP endpoint wiring, audit writer, sync loop.
