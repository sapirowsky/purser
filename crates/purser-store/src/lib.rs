//! Purser local store: SQLite migrations + repositories (one DB per device).
//!
//! The schema bakes in both seams from migration one — see `migrations/001_init.sql`.
//! Values are NEVER stored as plaintext: `secrets` holds no value column; ciphertext
//! lives only in `secret_versions`, and `audit_events` never records a value.

/// SQL for the initial schema. Applied via rusqlite once the DB layer is wired up.
pub const MIGRATION_001_INIT: &str = include_str!("../migrations/001_init.sql");

/// All migrations, in application order: `(name, sql)`.
pub fn migrations() -> &'static [(&'static str, &'static str)] {
    &[("001_init", MIGRATION_001_INIT)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_embedded_and_nonempty() {
        assert!(MIGRATION_001_INIT.contains("CREATE TABLE"));
        assert_eq!(migrations().len(), 1);
    }
}
