//! Purser core types.
//!
//! Two load-bearing seams live here from day one (see the planning repo,
//! docs/notes/tech-stack.md):
//!   * Seam 1 — opaque, permanent identity. Paths and git remotes are *projections*,
//!     never identity. This keeps the object-storage / no-filesystem future reachable.
//!   * Seam 2 — capabilities are granted over a *generic* resource. v1 only ever grants
//!     over secrets, but the shape already fits files, commits, and branches — which is
//!     the permissioned-git future.

/// An opaque, permanent identifier (a ULID rendered as text).
///
/// Identity is never a path. A path/remote is one projection of the thing this Id names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(pub String);

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub type ProjectId = Id;
pub type SecretId = Id;

/// What a grant lets its subject do. Ordered least → most privileged.
///
/// `Use` is treated as effective value access (injecting a secret into a process
/// is equivalent to reading it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Metadata,
    Use,
    Manage,
}

/// The kind of thing a capability is granted over (seam 2).
///
/// v1 only ever constructs `Secret`. The other variants are intentionally named now so
/// the type — and the `grants` table — already fit the permissioned-git future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    Secret,
    // Future: File, Commit, Branch — reachable without a schema change.
}

/// A capability over a generic resource (seam 2).
#[derive(Debug, Clone)]
pub struct Grant {
    /// Who holds the grant — a device id, an agent session, or a user.
    pub subject: String,
    pub capability: Capability,
    pub resource_type: ResourceType,
    pub resource_id: Id,
}
