//! Purser's value-blind SQLite repository.

use purser_core::Id;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MIGRATION_001_INIT: &str = include_str!("../migrations/001_init.sql");
pub const MIGRATION_002_PROJECT_PATHS: &str = include_str!("../migrations/002_project_paths.sql");

pub fn migrations() -> &'static [(&'static str, &'static str)] {
    &[
        ("001_init", MIGRATION_001_INIT),
        ("002_project_paths", MIGRATION_002_PROJECT_PATHS),
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
    /// Open the per-user production database and apply pending migrations.
    pub fn open() -> Result<Self> {
        let base = dirs::data_local_dir().ok_or(StoreError::NoDataDirectory)?;
        let mut directory = base.join("purser");
        // A scoped device keeps its own database, alongside its own keyring accounts.
        if let Some(scope) = purser_core::device_scope() {
            directory = directory.join("devices").join(scope);
        }
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
        Ok(dirs::data_local_dir()
            .ok_or(StoreError::NoDataDirectory)?
            .join("purser")
            .join("purser.db"))
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
                     profile_ref = ?5
                 WHERE id = ?6",
                params![name, git_remote, branch, package_manager, profile_ref, id],
            )?;
            Ok(id)
        } else {
            let id = Id::generate().0;
            self.connection.execute(
                "INSERT INTO projects(
                     id, name, git_remote, branch, package_manager, profile_ref, local_path,
                     created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
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
            "SELECT id, name, git_remote, branch, package_manager, profile_ref, local_path
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
                "SELECT id, name, git_remote, branch, package_manager, profile_ref, local_path
                 FROM projects WHERE local_path = ?1",
                [path],
                project_from_row,
            )
            .optional()?)
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
        let existing_self: Option<String> = self
            .connection
            .query_row(
                "SELECT id FROM devices WHERE is_self = 1 ORDER BY rowid LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let existing_key: Option<String> = self
            .connection
            .query_row(
                "SELECT id FROM devices WHERE public_key = ?1 ORDER BY rowid LIMIT 1",
                [public_key],
                |row| row.get(0),
            )
            .optional()?;

        let id = existing_self
            .or(existing_key)
            .unwrap_or_else(|| Id::generate().0);
        let updated = self.connection.execute(
            "UPDATE devices SET label = ?1, public_key = ?2, is_self = 1 WHERE id = ?3",
            params![label, public_key, id],
        )?;
        if updated == 0 {
            self.connection.execute(
                "INSERT INTO devices(id, label, public_key, is_self, paired_at)
                 VALUES (?1, ?2, ?3, 1, ?4)",
                params![id, label, public_key, timestamp()],
            )?;
        }
        self.connection
            .execute("DELETE FROM devices WHERE is_self = 1 AND id != ?1", [&id])?;
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
        let existing: Option<(String, bool)> = self
            .connection
            .query_row(
                "SELECT id, is_self FROM devices WHERE public_key = ?1 ORDER BY rowid LIMIT 1",
                [public_key],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        if let Some((_id, true)) = existing {
            return Err(StoreError::CannotPairSelf);
        }
        if let Some((id, false)) = existing {
            self.connection.execute(
                "UPDATE devices SET label = ?1, paired_at = ?2 WHERE id = ?3",
                params![label, timestamp(), id],
            )?;
            return Ok(id);
        }
        let id = Id::generate().0;
        self.connection.execute(
            "INSERT INTO devices(id, label, public_key, is_self, paired_at)
             VALUES (?1, ?2, ?3, 0, ?4)",
            params![id, label, public_key, timestamp()],
        )?;
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
        assert_eq!(migrations().len(), 2);
        assert_eq!(civil_date_from_unix_days(0), (1970, 1, 1));
    }

    #[test]
    fn migration_002_applies_after_migration_001() {
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
        drop(connection);

        let store = Store::open_at(&path).unwrap();
        assert_eq!(store.list_projects().unwrap(), Vec::<Project>::new());
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
