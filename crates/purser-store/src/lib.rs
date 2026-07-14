//! Purser's value-blind SQLite repository.

use purser_core::Id;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MIGRATION_001_INIT: &str = include_str!("../migrations/001_init.sql");

pub fn migrations() -> &'static [(&'static str, &'static str)] {
    &[("001_init", MIGRATION_001_INIT)]
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the operating system did not provide a local data directory")]
    NoDataDirectory,
    #[error("could not create Purser's data directory: {0}")]
    CreateDataDirectory(#[source] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
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

pub struct Store {
    connection: Connection,
}

impl Store {
    /// Open the per-user production database and apply pending migrations.
    pub fn open() -> Result<Self> {
        let base = dirs::data_local_dir().ok_or(StoreError::NoDataDirectory)?;
        let directory = base.join("purser");
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
        assert_eq!(migrations().len(), 1);
        assert_eq!(civil_date_from_unix_days(0), (1970, 1, 1));
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
