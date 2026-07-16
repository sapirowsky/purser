//! Purser's value-blind SQLite repository.

use purser_core::Id;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MIGRATION_001_INIT: &str = include_str!("../migrations/001_init.sql");
pub const MIGRATION_002_PROJECT_PATHS: &str = include_str!("../migrations/002_project_paths.sql");
pub const MIGRATION_003_MANIFEST_SYNC: &str = include_str!("../migrations/003_manifest_sync.sql");
pub const MIGRATION_004_DEVICE_UNIQUENESS: &str =
    include_str!("../migrations/004_device_uniqueness.sql");

pub fn migrations() -> &'static [(&'static str, &'static str)] {
    &[
        ("001_init", MIGRATION_001_INIT),
        ("002_project_paths", MIGRATION_002_PROJECT_PATHS),
        ("003_manifest_sync", MIGRATION_003_MANIFEST_SYNC),
        ("004_device_uniqueness", MIGRATION_004_DEVICE_UNIQUENESS),
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the operating system did not provide a local data directory")]
    NoDataDirectory,
    #[error("could not create Purser's data directory: {0}")]
    CreateDataDirectory(#[source] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("this device cannot be recorded as its own paired peer")]
    CannotPairSelf,
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSummary {
    pub name: String,
    pub configured: bool,
}

/// One at-rest version joined with the metadata needed to construct an encrypted sync
/// payload. Values remain ciphertext in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncSecretVersion {
    pub secret_id: String,
    pub name: String,
    pub profile: String,
    pub group: Option<String>,
    pub version: i64,
    pub ciphertext: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretIdentity {
    pub id: String,
    pub name: String,
    pub profile: String,
    pub group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSecretVersion {
    pub ciphertext: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub session_id: Option<String>,
    pub kind: String,
    pub secret_ref: Option<String>,
    pub decision: String,
    pub prev_hash: Option<String>,
    pub hash: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub git_remote: Option<String>,
    pub branch: Option<String>,
    pub package_manager: Option<String>,
    pub profile_ref: Option<String>,
    pub local_path: Option<String>,
    pub updated_at: String,
}

/// The portable portion of a project manifest. A local path cannot be represented here.
pub struct SyncProject<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub git_remote: Option<&'a str>,
    pub branch: Option<&'a str>,
    pub package_manager: Option<&'a str>,
    pub profile_ref: Option<&'a str>,
    pub updated_at: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub label: String,
    pub public_key: Vec<u8>,
    pub is_self: bool,
    pub paired_at: String,
}

pub struct Store {
    connection: Connection,
}

impl Store {
    /// The data directory for the device in effect. A scoped device (`PURSER_DEVICE`) keeps
    /// its own directory, alongside its own keyring accounts; the real device uses the root.
    ///
    /// One builder feeds both [`Self::open`] and [`Self::database_path`] so a scoped device
    /// can never open one database while reporting another.
    fn scoped_data_dir() -> Result<PathBuf> {
        let mut directory = dirs::data_local_dir()
            .ok_or(StoreError::NoDataDirectory)?
            .join("purser");
        if let Some(scope) = purser_core::device_scope() {
            directory = directory.join("devices").join(scope);
        }
        Ok(directory)
    }

    /// Open the per-user production database and apply pending migrations.
    pub fn open() -> Result<Self> {
        let directory = Self::scoped_data_dir()?;
        std::fs::create_dir_all(&directory).map_err(StoreError::CreateDataDirectory)?;
        Self::open_at(directory.join("purser.db"))
    }

    /// Open a database at an explicit path. This is also useful to isolated tests.
    pub fn open_at(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        let mut store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        let mut store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn database_path() -> Result<PathBuf> {
        Ok(Self::scoped_data_dir()?.join("purser.db"))
    }

    fn initialize(&mut self) -> Result<()> {
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 name TEXT PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );",
        )?;

        for (name, sql) in migrations() {
            let applied: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = ?1)",
                [name],
                |row| row.get(0),
            )?;
            if !applied {
                let transaction = self.connection.transaction()?;
                transaction.execute_batch(sql)?;
                transaction.execute(
                    "INSERT INTO schema_migrations(name, applied_at) VALUES (?1, ?2)",
                    params![name, timestamp()],
                )?;
                transaction.commit()?;
            }
        }
        Ok(())
    }

    /// Create or update secret metadata and return its opaque id.
    pub fn upsert_secret(
        &self,
        name: &str,
        profile: &str,
        group: Option<&str>,
        configured: bool,
    ) -> Result<String> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT id FROM secrets WHERE name = ?1 AND profile = ?2 ORDER BY rowid LIMIT 1",
                params![name, profile],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing {
            self.connection.execute(
                "UPDATE secrets SET group_name = COALESCE(?1, group_name), configured = ?2 WHERE id = ?3",
                params![group, configured as i64, id],
            )?;
            Ok(id)
        } else {
            let id = Id::generate().0;
            self.connection.execute(
                "INSERT INTO secrets(id, name, group_name, profile, configured, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![id, name, group, profile, configured as i64, timestamp()],
            )?;
            Ok(id)
        }
    }

    /// Append the next encrypted version, retaining every earlier version.
    pub fn add_secret_version(&self, secret_id: &str, ciphertext: &[u8]) -> Result<i64> {
        let version: i64 = self.connection.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM secret_versions WHERE secret_id = ?1",
            [secret_id],
            |row| row.get(0),
        )?;
        self.connection.execute(
            "INSERT INTO secret_versions(id, secret_id, version, ciphertext, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Id::generate().0,
                secret_id,
                version,
                ciphertext,
                timestamp()
            ],
        )?;
        Ok(version)
    }

    /// Pairing must not install a different vault key over ciphertext already stored here.
    pub fn has_secret_versions(&self) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM secret_versions LIMIT 1)",
            [],
            |row| row.get(0),
        )?)
    }

    /// Return every secret version for full-exchange replication. No cursor is consulted.
    pub fn all_secret_versions_for_sync(&self) -> Result<Vec<SyncSecretVersion>> {
        let mut statement = self.connection.prepare(
            "SELECT s.id, s.name, s.profile, s.group_name,
                    v.version, v.ciphertext, v.created_at
             FROM secrets s
             JOIN secret_versions v ON v.secret_id = s.id
             ORDER BY s.id, v.version",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(SyncSecretVersion {
                secret_id: row.get(0)?,
                name: row.get(1)?,
                profile: row.get(2)?,
                group: row.get(3)?,
                version: row.get(4)?,
                ciphertext: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn find_secret_by_id(&self, id: &str) -> Result<Option<SecretIdentity>> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, name, profile, group_name FROM secrets WHERE id = ?1",
                [id],
                |row| {
                    Ok(SecretIdentity {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        profile: row.get(2)?,
                        group: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn find_secret_by_name_profile(
        &self,
        name: &str,
        profile: &str,
    ) -> Result<Option<SecretIdentity>> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, name, profile, group_name
                 FROM secrets WHERE name = ?1 AND profile = ?2 ORDER BY rowid LIMIT 1",
                params![name, profile],
                |row| {
                    Ok(SecretIdentity {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        profile: row.get(2)?,
                        group: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn find_secret_version(
        &self,
        secret_id: &str,
        version: i64,
    ) -> Result<Option<StoredSecretVersion>> {
        Ok(self
            .connection
            .query_row(
                "SELECT ciphertext, created_at FROM secret_versions
                 WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
                |row| {
                    Ok(StoredSecretVersion {
                        ciphertext: row.get(0)?,
                        created_at: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    /// Insert metadata using the portable ULID supplied by an authorized peer.
    pub fn insert_synced_secret(
        &self,
        id: &str,
        name: &str,
        profile: &str,
        group: Option<&str>,
        created_at: &str,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO secrets(id, name, group_name, profile, configured, created_at)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            params![id, name, group, profile, created_at],
        )?;
        Ok(())
    }

    pub fn insert_synced_secret_version(
        &self,
        secret_id: &str,
        version: i64,
        ciphertext: &[u8],
        created_at: &str,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO secret_versions(id, secret_id, version, ciphertext, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![Id::generate().0, secret_id, version, ciphertext, created_at],
        )?;
        Ok(())
    }

    /// Receiving any value version makes the local projection configured.
    pub fn mark_synced_secret_configured(
        &self,
        secret_id: &str,
        group: Option<&str>,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE secrets SET configured = 1, group_name = COALESCE(?1, group_name)
             WHERE id = ?2",
            params![group, secret_id],
        )?;
        Ok(())
    }

    /// LWW replacement for one concurrently-created `(secret_id, version)` row.
    pub fn replace_synced_secret_version(
        &self,
        secret_id: &str,
        version: i64,
        ciphertext: &[u8],
        created_at: &str,
    ) -> Result<()> {
        self.connection.execute(
            "UPDATE secret_versions SET ciphertext = ?1, created_at = ?2
             WHERE secret_id = ?3 AND version = ?4",
            params![ciphertext, created_at, secret_id, version],
        )?;
        Ok(())
    }

    pub fn list_secrets(&self, profile: &str) -> Result<Vec<SecretSummary>> {
        let mut statement = self.connection.prepare(
            "SELECT name, configured FROM secrets WHERE profile = ?1 ORDER BY name COLLATE NOCASE",
        )?;
        let rows = statement.query_map([profile], |row| {
            Ok(SecretSummary {
                name: row.get(0)?,
                configured: row.get::<_, i64>(1)? != 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Create or update a project projection and return its opaque id.
    pub fn upsert_project(
        &self,
        name: &str,
        git_remote: Option<&str>,
        branch: Option<&str>,
        package_manager: Option<&str>,
        profile_ref: Option<&str>,
        local_path: &str,
    ) -> Result<String> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT id FROM projects WHERE local_path = ?1",
                [local_path],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing {
            self.connection.execute(
                "UPDATE projects
                 SET name = ?1, git_remote = ?2, branch = ?3, package_manager = ?4,
                     profile_ref = ?5, updated_at = ?6
                 WHERE id = ?7",
                params![
                    name,
                    git_remote,
                    branch,
                    package_manager,
                    profile_ref,
                    timestamp(),
                    id
                ],
            )?;
            Ok(id)
        } else {
            let id = Id::generate().0;
            self.connection.execute(
                "INSERT INTO projects(
                     id, name, git_remote, branch, package_manager, profile_ref, local_path,
                     created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                params![
                    id,
                    name,
                    git_remote,
                    branch,
                    package_manager,
                    profile_ref,
                    local_path,
                    timestamp()
                ],
            )?;
            Ok(id)
        }
    }

    pub fn list_projects(&self) -> Result<Vec<Project>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, git_remote, branch, package_manager, profile_ref, local_path,
                    updated_at
             FROM projects ORDER BY rowid",
        )?;
        let rows = statement.query_map([], project_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Unregister a project. Returns whether a row matched.
    ///
    /// Only the manifest projection is dropped; the working tree and the profile's secrets
    /// are untouched.
    pub fn remove_project_by_path(&self, path: &str) -> Result<bool> {
        let removed = self
            .connection
            .execute("DELETE FROM projects WHERE local_path = ?1", [path])?;
        Ok(removed > 0)
    }

    pub fn find_project_by_path(&self, path: &str) -> Result<Option<Project>> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, name, git_remote, branch, package_manager, profile_ref, local_path,
                        updated_at
                 FROM projects WHERE local_path = ?1",
                [path],
                project_from_row,
            )
            .optional()?)
    }

    pub fn find_project_by_id(&self, id: &str) -> Result<Option<Project>> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, name, git_remote, branch, package_manager, profile_ref, local_path,
                        updated_at
                 FROM projects WHERE id = ?1",
                [id],
                project_from_row,
            )
            .optional()?)
    }

    pub fn find_project_by_name(&self, name: &str) -> Result<Option<Project>> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, name, git_remote, branch, package_manager, profile_ref, local_path,
                        updated_at
                 FROM projects WHERE name = ?1 ORDER BY rowid LIMIT 1",
                [name],
                project_from_row,
            )
            .optional()?)
    }

    /// Insert a portable project received from a peer. Paths are device-local and absent.
    pub fn insert_synced_project(&self, project: &SyncProject<'_>) -> Result<()> {
        self.connection.execute(
            "INSERT INTO projects(
                 id, name, git_remote, branch, package_manager, profile_ref, local_path,
                 created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)",
            params![
                project.id,
                project.name,
                project.git_remote,
                project.branch,
                project.package_manager,
                project.profile_ref,
                project.updated_at
            ],
        )?;
        Ok(())
    }

    /// Replace only portable fields. The existing path belongs to this device and survives.
    pub fn update_synced_project(&self, project: &SyncProject<'_>) -> Result<()> {
        self.connection.execute(
            "UPDATE projects
             SET name = ?1, git_remote = ?2, branch = ?3, package_manager = ?4,
                 profile_ref = ?5, updated_at = ?6
             WHERE id = ?7",
            params![
                project.name,
                project.git_remote,
                project.branch,
                project.package_manager,
                project.profile_ref,
                project.updated_at,
                project.id
            ],
        )?;
        Ok(())
    }

    /// Set this device's path projection without making it a replicated manifest edit.
    pub fn set_project_local_path(&self, id: &str, local_path: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE projects SET local_path = ?1 WHERE id = ?2",
            params![local_path, id],
        )?;
        Ok(())
    }

    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO settings(key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                updated_at = excluded.updated_at",
            params![key, value, timestamp()],
        )?;
        Ok(())
    }

    /// Return only each configured secret's name and latest ciphertext.
    pub fn get_active_versions(&self, profile: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let mut statement = self.connection.prepare(
            "SELECT s.name, v.ciphertext
             FROM secrets s
             JOIN secret_versions v ON v.secret_id = s.id
             WHERE s.profile = ?1 AND s.configured = 1
               AND v.version = (SELECT MAX(v2.version) FROM secret_versions v2 WHERE v2.secret_id = s.id)
             ORDER BY s.name COLLATE NOCASE",
        )?;
        let rows = statement.query_map([profile], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn all_secret_names(&self) -> Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT name FROM secrets ORDER BY name COLLATE NOCASE")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Record this installation's identity, preserving exactly one self row.
    pub fn upsert_self_device(&self, label: &str, public_key: &[u8]) -> Result<String> {
        // Read-then-write across three statements: run them in one transaction so a crash or
        // a concurrent process can never leave two self rows or a self row without its key.
        let tx = self.connection.unchecked_transaction()?;
        let existing_self: Option<String> = tx
            .query_row(
                "SELECT id FROM devices WHERE is_self = 1 ORDER BY rowid LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let existing_key: Option<String> = tx
            .query_row(
                "SELECT id FROM devices WHERE public_key = ?1 ORDER BY rowid LIMIT 1",
                [public_key],
                |row| row.get(0),
            )
            .optional()?;

        let id = existing_self
            .or(existing_key)
            .unwrap_or_else(|| Id::generate().0);
        // Remove any OTHER self rows FIRST. Promoting this row to is_self = 1 while a second
        // self row still exists would trip the partial unique index (004); deleting first
        // keeps the "exactly one self" invariant true at every statement boundary.
        tx.execute("DELETE FROM devices WHERE is_self = 1 AND id != ?1", [&id])?;
        let updated = tx.execute(
            "UPDATE devices SET label = ?1, public_key = ?2, is_self = 1 WHERE id = ?3",
            params![label, public_key, id],
        )?;
        if updated == 0 {
            tx.execute(
                "INSERT INTO devices(id, label, public_key, is_self, paired_at)
                 VALUES (?1, ?2, ?3, 1, ?4)",
                params![id, label, public_key, timestamp()],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut statement = self.connection.prepare(
            "SELECT id, label, public_key, is_self, paired_at
             FROM devices ORDER BY is_self DESC, label COLLATE NOCASE, rowid",
        )?;
        let rows = statement.query_map([], device_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub fn find_device_by_public_key(&self, public_key: &[u8]) -> Result<Option<Device>> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, label, public_key, is_self, paired_at
                 FROM devices WHERE public_key = ?1 ORDER BY rowid LIMIT 1",
                [public_key],
                device_from_row,
            )
            .optional()?)
    }

    /// Record a successfully paired peer without ever changing the self-device row.
    pub fn upsert_paired_device(&self, label: &str, public_key: &[u8]) -> Result<String> {
        // One transaction so the lookup and the insert/update cannot interleave with another
        // process and produce two rows for the same peer public key.
        let tx = self.connection.unchecked_transaction()?;
        let existing: Option<(String, bool)> = tx
            .query_row(
                "SELECT id, is_self FROM devices WHERE public_key = ?1 ORDER BY rowid LIMIT 1",
                [public_key],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        // The diverging `return` means `existing` is only moved past here when it did NOT
        // match a self row, so it stays usable below.
        if let Some((_id, true)) = existing {
            return Err(StoreError::CannotPairSelf);
        }
        let id = existing
            .map(|(id, _)| id)
            .unwrap_or_else(|| Id::generate().0);
        // UNIQUE(public_key) (004) makes this idempotent even if a concurrent writer inserted
        // the same peer between the SELECT and here: the insert folds into an update instead
        // of raising a constraint error. The WHERE guard keeps it from ever touching a self
        // row (whose is_self we must never clear).
        tx.execute(
            "INSERT INTO devices(id, label, public_key, is_self, paired_at)
             VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(public_key) DO UPDATE SET label = excluded.label, paired_at = excluded.paired_at
               WHERE devices.is_self = 0",
            params![id, label, public_key, timestamp()],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub fn open_session(&self, kind: &str, scope: Option<&str>) -> Result<String> {
        let id = Id::generate().0;
        self.connection.execute(
            "INSERT INTO sessions(id, kind, scope, started_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, kind, scope, timestamp()],
        )?;
        Ok(id)
    }

    pub fn close_session(&self, session_id: &str) -> Result<()> {
        self.connection.execute(
            "UPDATE sessions SET ended_at = ?1 WHERE id = ?2",
            params![timestamp(), session_id],
        )?;
        Ok(())
    }

    pub fn append_audit_event(
        &self,
        session_id: Option<&str>,
        kind: &str,
        secret_ref: Option<&str>,
        decision: &str,
    ) -> Result<AuditEvent> {
        let prev_hash: Option<String> = self
            .connection
            .query_row(
                "SELECT hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let id = Id::generate().0;
        let created_at = timestamp();
        let hash = audit_hash(
            prev_hash.as_deref(),
            &id,
            kind,
            secret_ref,
            decision,
            &created_at,
        );
        self.connection.execute(
            "INSERT INTO audit_events(id, session_id, kind, secret_ref, decision, prev_hash, hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, session_id, kind, secret_ref, decision, prev_hash, hash, created_at],
        )?;
        Ok(AuditEvent {
            id,
            session_id: session_id.map(str::to_owned),
            kind: kind.to_owned(),
            secret_ref: secret_ref.map(str::to_owned),
            decision: decision.to_owned(),
            prev_hash,
            hash,
            created_at,
        })
    }

    pub fn recent_events(&self) -> Result<Vec<AuditEvent>> {
        self.query_events(
            "SELECT id, session_id, kind, secret_ref, decision, prev_hash, hash, created_at
             FROM audit_events
             WHERE session_id = (SELECT id FROM sessions ORDER BY rowid DESC LIMIT 1)
             ORDER BY rowid",
        )
    }

    pub fn denied_events(&self) -> Result<Vec<AuditEvent>> {
        self.query_events(
            "SELECT id, session_id, kind, secret_ref, decision, prev_hash, hash, created_at
             FROM audit_events WHERE decision = 'denied' ORDER BY rowid DESC",
        )
    }

    fn query_events(&self, sql: &str) -> Result<Vec<AuditEvent>> {
        let mut statement = self.connection.prepare(sql)?;
        let rows = statement.query_map([], |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                session_id: row.get(1)?,
                kind: row.get(2)?,
                secret_ref: row.get(3)?,
                decision: row.get(4)?,
                prev_hash: row.get(5)?,
                hash: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}

fn project_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        git_remote: row.get(2)?,
        branch: row.get(3)?,
        package_manager: row.get(4)?,
        profile_ref: row.get(5)?,
        local_path: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Device> {
    Ok(Device {
        id: row.get(0)?,
        label: row.get(1)?,
        public_key: row.get(2)?,
        is_self: row.get::<_, i64>(3)? != 0,
        paired_at: row.get(4)?,
    })
}

fn timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch");
    let total_seconds = duration.as_secs();
    let days = (total_seconds / 86_400) as i64;
    let seconds_in_day = total_seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days(days);
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:09}Z",
        duration.subsec_nanos()
    )
}

/// Nanoseconds since the Unix epoch for a `created_at` written by [`timestamp`].
///
/// Ordering timestamps by string comparison would be wrong: this database already holds
/// two formats, because an earlier build wrote raw epoch seconds (`1784057032.061923000Z`)
/// before the current civil-date form (`2026-07-15T09:44:28.637998600Z`) replaced it.
/// Lexically every legacy row sorts before every modern one regardless of when it was
/// actually written. Both forms are parsed here so callers can order them by real time,
/// and so a future format change cannot silently corrupt an ordering again.
///
/// Returns `None` for anything unrecognized; callers must treat that as "cannot order"
/// rather than as "older".
pub fn unix_nanos_from_timestamp(timestamp: &str) -> Option<i128> {
    let body = timestamp.strip_suffix('Z')?;
    let (head, nanos) = body.split_once('.')?;
    if nanos.len() != 9 || !nanos.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let nanos: i128 = nanos.parse().ok()?;

    let seconds = match head.split_once('T') {
        Some((date, time)) => {
            let (year, month, day) = parse_triplet(date, '-')?;
            let (hour, minute, second) = parse_triplet(time, ':')?;
            // Bound the year to keep `unix_days_from_civil`'s i64 arithmetic far from
            // overflow: a crafted timestamp must return None, never panic or wrap. All real
            // timestamps this parses are 4-digit-year civil dates written by `timestamp`.
            if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
                return None;
            }
            if day < 1 || day > days_in_month(year, month) {
                return None;
            }
            if hour > 23 || minute > 59 || second > 59 {
                return None;
            }
            unix_days_from_civil(year, month, day) as i128 * 86_400
                + hour as i128 * 3_600
                + minute as i128 * 60
                + second as i128
        }
        // The legacy form: whole seconds since the epoch, no civil date.
        None => head.parse::<i64>().ok()? as i128,
    };
    Some(seconds * 1_000_000_000 + nanos)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn parse_triplet(text: &str, separator: char) -> Option<(i64, i64, i64)> {
    let mut parts = text.split(separator);
    let first = parts.next()?.parse().ok()?;
    let second = parts.next()?.parse().ok()?;
    let third = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((first, second, third))
}

/// Inverse of [`civil_date_from_unix_days`] (Howard Hinnant's `days_from_civil`).
fn unix_days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn audit_hash(
    prev_hash: Option<&str>,
    id: &str,
    kind: &str,
    secret_ref: Option<&str>,
    decision: &str,
    created_at: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.unwrap_or_default().as_bytes());
    hasher.update(id.as_bytes());
    hasher.update(kind.as_bytes());
    hasher.update(secret_ref.unwrap_or_default().as_bytes());
    hasher.update(decision.as_bytes());
    hasher.update(created_at.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_embedded_and_nonempty() {
        assert!(MIGRATION_001_INIT.contains("CREATE TABLE"));
        assert!(MIGRATION_002_PROJECT_PATHS.contains("ALTER TABLE"));
        assert!(MIGRATION_003_MANIFEST_SYNC.contains("CREATE TABLE settings"));
        assert!(MIGRATION_004_DEVICE_UNIQUENESS.contains("CREATE UNIQUE INDEX"));
        assert_eq!(migrations().len(), 4);
        assert_eq!(civil_date_from_unix_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_days_round_trip_against_their_inverse() {
        for days in [-25_567_i64, -1, 0, 1, 19_000, 20_284, 100_000] {
            let (year, month, day) = civil_date_from_unix_days(days);
            assert_eq!(unix_days_from_civil(year, month, day), days, "{days}");
        }
        // Leap day, the classic off-by-one in this algorithm.
        assert_eq!(
            civil_date_from_unix_days(unix_days_from_civil(2024, 2, 29)),
            (2024, 2, 29)
        );
    }

    #[test]
    fn timestamps_parse_back_to_the_instant_they_were_written_from() {
        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let parsed = unix_nanos_from_timestamp(&timestamp()).expect("own format must parse");
        let after = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!(parsed >= before.as_nanos() as i128 && parsed <= after.as_nanos() as i128);
    }

    #[test]
    fn both_stored_timestamp_formats_parse_to_the_same_instant() {
        // These two forms are both present in a real Purser database, because an early
        // build wrote raw epoch seconds before the civil-date form replaced it.
        // 1784057032 IS 2026-07-14T19:23:52Z, and only parsing can tell you that.
        assert_eq!(
            unix_nanos_from_timestamp("1784057032.061923000Z"),
            unix_nanos_from_timestamp("2026-07-14T19:23:52.061923000Z")
        );
        assert_eq!(
            unix_nanos_from_timestamp("1970-01-01T00:00:00.000000000Z"),
            Some(0)
        );
        assert_eq!(unix_nanos_from_timestamp("0.000000000Z"), Some(0));
    }

    #[test]
    fn string_order_disagrees_with_real_time_across_the_two_formats() {
        // Every legacy row this project actually holds predates the format change, and an
        // epoch from this era starts with '1' while a civil date starts with '2' — so for
        // real data, string order happens to agree with real time. It is coincidence, not
        // a property: an epoch outside 2001-09-09..2033-05-18 breaks it, and so would the
        // next format change. Order by instant so correctness never rests on the luck.
        let older_epoch = "999999999.000000000Z"; // 2001-09-09
        let newer_civil = "2026-07-14T19:27:16.358278100Z";

        assert!(
            older_epoch > newer_civil,
            "string order puts the older row last"
        );
        assert!(
            unix_nanos_from_timestamp(older_epoch) < unix_nanos_from_timestamp(newer_civil),
            "real time puts it first"
        );
    }

    #[test]
    fn unorderable_timestamps_are_rejected_rather_than_guessed() {
        for bad in [
            "",
            "Z",
            "not-a-time",
            "2026-07-14T19:27:16Z",           // no nanoseconds
            "2026-07-14T19:27:16.1234Z",      // wrong nanosecond width
            "2026-13-01T00:00:00.000000000Z", // month out of range
            "2026-07-14T25:00:00.000000000Z", // hour out of range
            "2026-07-14T19:27:16.358278100",  // no trailing Z
            "2026-02-30T00:00:00.000000000Z", // February never has 30 days
            "2025-02-29T00:00:00.000000000Z", // 2025 is not a leap year
            "2026-04-31T00:00:00.000000000Z", // April has 30 days
            "2026-00-10T00:00:00.000000000Z", // month zero
            "2026-07-00T00:00:00.000000000Z", // day zero
            "999999999999-01-01T00:00:00.000000000Z", // year would overflow the day math
        ] {
            assert_eq!(unix_nanos_from_timestamp(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn real_leap_days_still_parse() {
        // The validation must not reject genuine dates, including leap-year February 29.
        for good in [
            "2024-02-29T12:00:00.000000000Z", // 2024 is a leap year
            "2000-02-29T00:00:00.000000000Z", // divisible by 400
            "2026-01-31T23:59:59.000000000Z",
            "2026-12-31T00:00:00.000000000Z",
        ] {
            assert!(unix_nanos_from_timestamp(good).is_some(), "{good:?}");
        }
    }

    #[test]
    fn migrations_002_and_003_apply_to_an_existing_project() {
        let path = std::env::temp_dir().join(format!("purser-{}.db", Id::generate()));
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (
                     name TEXT PRIMARY KEY,
                     applied_at TEXT NOT NULL
                 );",
            )
            .unwrap();
        connection.execute_batch(MIGRATION_001_INIT).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(name, applied_at) VALUES ('001_init', 'now')",
                [],
            )
            .unwrap();
        let created_at = "2026-07-15T12:00:00.000000000Z";
        connection
            .execute(
                "INSERT INTO projects(id, name, created_at) VALUES ('01EXISTING', 'existing', ?1)",
                [created_at],
            )
            .unwrap();
        drop(connection);

        let store = Store::open_at(&path).unwrap();
        let projects = store.list_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].updated_at, created_at);
        assert_eq!(projects[0].local_path, None);
        assert_eq!(store.setting("projects_root").unwrap(), None);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn project_upsert_updates_existing_path() {
        let store = Store::open_in_memory().unwrap();
        let first_id = store
            .upsert_project(
                "first",
                Some("first-remote"),
                Some("main"),
                Some("npm"),
                None,
                "/projects/example",
            )
            .unwrap();
        let second_id = store
            .upsert_project(
                "second",
                Some("second-remote"),
                Some("trunk"),
                Some("pnpm"),
                Some("local"),
                "/projects/example",
            )
            .unwrap();

        let projects = store.list_projects().unwrap();
        assert_eq!(first_id, second_id);
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "second");
        assert_eq!(projects[0].package_manager.as_deref(), Some("pnpm"));
    }

    #[test]
    fn settings_round_trip_and_project_timestamps_are_initialized() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.setting("projects_root").unwrap(), None);
        store
            .set_setting("projects_root", "/work/projects")
            .unwrap();
        assert_eq!(
            store.setting("projects_root").unwrap().as_deref(),
            Some("/work/projects")
        );
        store.set_setting("projects_root", "/new/projects").unwrap();
        assert_eq!(
            store.setting("projects_root").unwrap().as_deref(),
            Some("/new/projects")
        );

        store
            .upsert_project("example", None, None, None, None, "/work/example")
            .unwrap();
        assert!(unix_nanos_from_timestamp(&store.list_projects().unwrap()[0].updated_at).is_some());
    }

    #[test]
    fn self_device_upsert_is_idempotent() {
        let store = Store::open_in_memory().unwrap();
        let first = store
            .upsert_self_device("first label", &[3_u8; 32])
            .unwrap();
        let second = store
            .upsert_self_device("updated label", &[3_u8; 32])
            .unwrap();
        let third = store
            .upsert_self_device("rotated key", &[4_u8; 32])
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(second, third);
        assert_eq!(store.list_devices().unwrap().len(), 1);
        assert_eq!(store.list_devices().unwrap()[0].label, "rotated key");
        assert!(
            store
                .find_device_by_public_key(&[4_u8; 32])
                .unwrap()
                .unwrap()
                .is_self
        );
    }

    #[test]
    fn paired_upsert_is_idempotent_by_public_key() {
        // The same peer paired twice (e.g. a relabel) must stay one row, not two — the
        // schema's UNIQUE(public_key) folds the second insert into an update.
        let store = Store::open_in_memory().unwrap();
        let first = store.upsert_paired_device("laptop", &[7_u8; 32]).unwrap();
        let second = store
            .upsert_paired_device("laptop-renamed", &[7_u8; 32])
            .unwrap();
        assert_eq!(first, second);
        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].label, "laptop-renamed");
        assert!(!devices[0].is_self);
    }

    #[test]
    fn the_schema_rejects_a_duplicate_public_key() {
        // Prove the index is really enforced, not just relied upon by the upsert helpers.
        let store = Store::open_in_memory().unwrap();
        store.upsert_paired_device("a", &[9_u8; 32]).unwrap();
        let raw = store.connection.execute(
            "INSERT INTO devices(id, label, public_key, is_self, paired_at)
             VALUES ('dup', 'b', ?1, 0, 'now')",
            params![&[9_u8; 32][..]],
        );
        assert!(raw.is_err(), "a duplicate public_key must be rejected");
        assert_eq!(store.list_devices().unwrap().len(), 1);
    }

    #[test]
    fn paired_peer_upsert_never_converts_the_self_row() {
        let store = Store::open_in_memory().unwrap();
        store.upsert_self_device("self", &[3_u8; 32]).unwrap();
        assert!(matches!(
            store.upsert_paired_device("not-self", &[3_u8; 32]),
            Err(StoreError::CannotPairSelf)
        ));
        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].is_self);
        assert_eq!(devices[0].label, "self");
    }

    #[test]
    fn secret_version_presence_is_an_explicit_pairing_guard() {
        let store = Store::open_in_memory().unwrap();
        assert!(!store.has_secret_versions().unwrap());
        let id = store.upsert_secret("TOKEN", "local", None, true).unwrap();
        store.add_secret_version(&id, b"opaque").unwrap();
        assert!(store.has_secret_versions().unwrap());
    }

    #[test]
    fn removing_a_project_drops_only_the_manifest_row() {
        let store = Store::open_in_memory().unwrap();
        let secret_id = store
            .upsert_secret("API_TOKEN", "local", None, true)
            .unwrap();
        store.add_secret_version(&secret_id, b"ciphertext").unwrap();
        store
            .upsert_project(
                "example",
                None,
                None,
                None,
                Some("local"),
                "/projects/example",
            )
            .unwrap();

        assert!(store.remove_project_by_path("/projects/example").unwrap());
        assert_eq!(store.list_projects().unwrap(), Vec::<Project>::new());
        // Unregistering a project must not disturb the profile's secrets.
        assert_eq!(store.list_secrets("local").unwrap().len(), 1);
        // A second removal reports that nothing matched rather than erroring.
        assert!(!store.remove_project_by_path("/projects/example").unwrap());
    }

    #[test]
    fn project_listing_never_contains_a_secret_value() {
        let store = Store::open_in_memory().unwrap();
        let secret_value = "project-list-must-never-contain-this-value";
        let secret_id = store
            .upsert_secret("API_TOKEN", "local", None, true)
            .unwrap();
        store
            .add_secret_version(&secret_id, secret_value.as_bytes())
            .unwrap();
        store
            .upsert_project(
                "example",
                None,
                None,
                None,
                Some("local"),
                "/projects/example",
            )
            .unwrap();

        assert!(!format!("{:?}", store.list_projects().unwrap()).contains(secret_value));
    }

    #[test]
    fn insert_and_list_exposes_metadata_not_values() {
        let store = Store::open_in_memory().unwrap();
        let known_value = "audit-must-never-contain-this-value";
        let id = store
            .upsert_secret("API_TOKEN", "local", Some("app"), true)
            .unwrap();
        store
            .add_secret_version(&id, known_value.as_bytes())
            .unwrap();

        let listed = store.list_secrets("local").unwrap();
        assert_eq!(
            listed,
            vec![SecretSummary {
                name: "API_TOKEN".into(),
                configured: true
            }]
        );
        assert!(!format!("{listed:?}").contains(known_value));
    }

    #[test]
    fn audit_hash_chain_links_and_never_serializes_a_value() {
        let store = Store::open_in_memory().unwrap();
        let secret_value = "known-super-secret-value-8417";
        let session = store.open_session("human", Some("local")).unwrap();
        let first = store
            .append_audit_event(Some(&session), "injected", Some("FIRST_NAME"), "used")
            .unwrap();
        let second = store
            .append_audit_event(Some(&session), "injected", Some("SECOND_NAME"), "used")
            .unwrap();
        let serialized = format!("{:?}", store.recent_events().unwrap());

        assert_eq!(second.prev_hash.as_deref(), Some(first.hash.as_str()));
        assert!(!serialized.contains(secret_value));
    }
}
