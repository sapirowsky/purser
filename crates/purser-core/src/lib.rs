//! Purser core types.
//!
//! Two load-bearing seams live here from day one (see the planning repo,
//! docs/notes/tech-stack.md):
//!   * Seam 1 — opaque, permanent identity. Paths and git remotes are *projections*,
//!     never identity. This keeps the object-storage / no-filesystem future reachable.
//!   * Seam 2 — capabilities are granted over a *generic* resource. v1 only ever grants
//!     over secrets, but the shape already fits files, commits, and branches — which is
//!     the permissioned-git future.

/// Names a separate Purser identity on one machine, for exercising multi-device sync
/// without a second physical box. Unset — the normal case — means the real device.
///
/// A scope must move the keyring accounts and the database together: a virtual device
/// reading the real device's rows with a virtual device's keys would decrypt nothing.
pub const DEVICE_SCOPE_VAR: &str = "PURSER_DEVICE";

/// The device scope in effect, if any. Blank is treated as unset.
pub fn device_scope() -> Option<String> {
    scope_from(std::env::var(DEVICE_SCOPE_VAR).ok().as_deref())
}

fn scope_from(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
}

/// An opaque, permanent identifier (a ULID rendered as text).
///
/// Identity is never a path. A path/remote is one projection of the thing this Id names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id(pub String);

impl Id {
    /// Generate a new opaque, lexicographically sortable identifier.
    pub fn generate() -> Self {
        Self(ulid::Ulid::new().to_string())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_device_scope_means_the_real_device() {
        // Guards against `PURSER_DEVICE=` (set but empty) quietly creating a second
        // identity whose keys and database the real device can never see again.
        assert_eq!(scope_from(None), None);
        assert_eq!(scope_from(Some("")), None);
        assert_eq!(scope_from(Some("   ")), None);
        assert_eq!(scope_from(Some(" mac-sim ")), Some("mac-sim".to_owned()));
    }

    #[test]
    fn generated_ids_are_valid_distinct_ulids() {
        let first = Id::generate();
        let second = Id::generate();
        assert_ne!(first, second);
        assert!(ulid::Ulid::from_string(&first.0).is_ok());
    }
}
