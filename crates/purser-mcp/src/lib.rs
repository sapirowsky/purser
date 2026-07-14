//! Purser MCP surface: what an AI agent is allowed to see.
//!
//! Metadata only. There is deliberately NO method that reveals, exports, hashes, or injects
//! a value. An agent that needs a secret to *run* something asks the daemon to launch the
//! process; the daemon injects and records — the value never crosses into the model context.
//!
//! Tools:
//!   secret_exists(profile, name) -> bool
//!   secret_list(profile)         -> names + configured status
//!   secret_usage(name)           -> declared references in the project

// TODO: implement the three tools over the store, wired through the daemon's MCP endpoint.
