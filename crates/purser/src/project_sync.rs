use anyhow::{anyhow, bail, Context, Result};
use purser_store::{Project, Store, SyncProject};
use purser_sync::Record;
use zeroize::{Zeroize, Zeroizing};

const RECORD_PREFIX: &str = "project:";
const PAYLOAD_MAGIC: &[u8; 8] = b"PURPROJ1";
const MAX_FIELD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SyncSummary {
    pub sent: usize,
    pub received: usize,
    pub skipped: usize,
    pub conflicted: usize,
    pub warnings: Vec<String>,
}

impl SyncSummary {
    pub fn render(&self) -> String {
        format!(
            "Projects: {} records sent, {} received, {} skipped, {} conflicted.",
            self.sent, self.received, self.skipped, self.conflicted
        )
    }
}

struct ProjectPayload {
    id: String,
    name: String,
    git_remote: Option<String>,
    branch: Option<String>,
    package_manager: Option<String>,
    profile_ref: Option<String>,
    updated_at: String,
}

impl Drop for ProjectPayload {
    fn drop(&mut self) {
        self.id.zeroize();
        self.name.zeroize();
        self.git_remote.zeroize();
        self.branch.zeroize();
        self.package_manager.zeroize();
        self.profile_ref.zeroize();
        self.updated_at.zeroize();
    }
}

pub(crate) fn is_project_record(record: &Record) -> bool {
    record.id.starts_with(RECORD_PREFIX)
}

pub(crate) fn build_records(store: &Store) -> Result<Vec<Record>> {
    build_records_with(store, |bytes| Ok(purser_vault::encrypt(bytes)?))
}

pub(crate) fn apply_records(store: &Store, records: &[Record]) -> Result<SyncSummary> {
    apply_records_with(store, records, |bytes| Ok(purser_vault::decrypt(bytes)?))
}

pub(crate) fn build_records_with<E>(store: &Store, mut encrypt: E) -> Result<Vec<Record>>
where
    E: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let projects = store.list_projects()?;
    let mut records = Vec::with_capacity(projects.len());
    for project in projects {
        let mut payload = encode_payload(&project)?;
        let ciphertext =
            encrypt(&payload).context("could not encrypt a project replication payload")?;
        payload.zeroize();
        records.push(Record {
            id: format!("{RECORD_PREFIX}{}", project.id),
            version: 1,
            ciphertext,
        });
    }
    Ok(records)
}

pub(crate) fn apply_records_with<D>(
    store: &Store,
    records: &[Record],
    mut decrypt: D,
) -> Result<SyncSummary>
where
    D: FnMut(&[u8]) -> Result<Zeroizing<Vec<u8>>>,
{
    let mut summary = SyncSummary::default();
    for record in records {
        let envelope_id = record
            .id
            .strip_prefix(RECORD_PREFIX)
            .ok_or_else(|| anyhow!("project sync record has the wrong namespace"))?;
        if record.version != 1 {
            bail!("project sync record has an unsupported version");
        }
        let mut plaintext = decrypt(&record.ciphertext)
            .context("could not decrypt a project replication payload")?;
        let payload = decode_payload(&plaintext)?;
        plaintext.zeroize();
        if payload.id != envelope_id {
            bail!("encrypted project payload identity does not match its record envelope");
        }

        let Some(existing) = store.find_project_by_id(&payload.id)? else {
            if let Some(name_match) = store.find_project_by_name(&payload.name)? {
                if name_match.id != payload.id {
                    summary.skipped += 1;
                    summary.conflicted += 1;
                    summary.warnings.push(format!(
                        "CONFLICT: incoming project {} has a different id; record skipped",
                        payload.name
                    ));
                    continue;
                }
            }
            store.insert_synced_project(&payload.as_sync_project())?;
            summary.received += 1;
            continue;
        };

        if portable_fields_equal(&existing, &payload) && existing.updated_at == payload.updated_at {
            summary.skipped += 1;
            continue;
        }

        summary.conflicted += 1;
        let Some(order) = compare_write_times(&payload.updated_at, &existing.updated_at) else {
            summary.skipped += 1;
            summary.warnings.push(format!(
                "CONFLICT: edits to project {}, but their write times cannot be ordered; kept the local manifest — resolve this one by hand",
                payload.name
            ));
            continue;
        };
        summary.warnings.push(format!(
            "CONFLICT: edits to project {}; last writer wins",
            payload.name
        ));
        if order.is_gt() {
            store.update_synced_project(&payload.as_sync_project())?;
            summary.received += 1;
        } else {
            summary.skipped += 1;
        }
    }
    Ok(summary)
}

impl ProjectPayload {
    fn as_sync_project(&self) -> SyncProject<'_> {
        SyncProject {
            id: &self.id,
            name: &self.name,
            git_remote: self.git_remote.as_deref(),
            branch: self.branch.as_deref(),
            package_manager: self.package_manager.as_deref(),
            profile_ref: self.profile_ref.as_deref(),
            updated_at: &self.updated_at,
        }
    }
}

fn portable_fields_equal(project: &Project, payload: &ProjectPayload) -> bool {
    project.name == payload.name
        && project.git_remote == payload.git_remote
        && project.branch == payload.branch
        && project.package_manager == payload.package_manager
        && project.profile_ref == payload.profile_ref
}

fn compare_write_times(incoming: &str, local: &str) -> Option<std::cmp::Ordering> {
    let incoming = purser_store::unix_nanos_from_timestamp(incoming)?;
    let local = purser_store::unix_nanos_from_timestamp(local)?;
    Some(incoming.cmp(&local))
}

fn encode_payload(project: &Project) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    output.extend_from_slice(PAYLOAD_MAGIC);
    write_bytes(&mut output, project.id.as_bytes())?;
    write_bytes(&mut output, project.name.as_bytes())?;
    write_optional(&mut output, project.git_remote.as_deref())?;
    write_optional(&mut output, project.branch.as_deref())?;
    write_optional(&mut output, project.package_manager.as_deref())?;
    write_optional(&mut output, project.profile_ref.as_deref())?;
    write_bytes(&mut output, project.updated_at.as_bytes())?;
    Ok(output)
}

fn decode_payload(encoded: &[u8]) -> Result<ProjectPayload> {
    let mut cursor = 0;
    if take(encoded, &mut cursor, PAYLOAD_MAGIC.len())? != PAYLOAD_MAGIC {
        bail!("incoming project sync payload has an invalid format");
    }
    let payload = ProjectPayload {
        id: read_string(encoded, &mut cursor)?,
        name: read_string(encoded, &mut cursor)?,
        git_remote: read_optional(encoded, &mut cursor)?,
        branch: read_optional(encoded, &mut cursor)?,
        package_manager: read_optional(encoded, &mut cursor)?,
        profile_ref: read_optional(encoded, &mut cursor)?,
        updated_at: read_string(encoded, &mut cursor)?,
    };
    if cursor != encoded.len() {
        bail!("incoming project sync payload has trailing bytes");
    }
    Ok(payload)
}

fn write_optional(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => write_bytes(output, value.as_bytes()),
        None => {
            output.extend_from_slice(&u32::MAX.to_be_bytes());
            Ok(())
        }
    }
}

fn read_optional(encoded: &[u8], cursor: &mut usize) -> Result<Option<String>> {
    let length = read_u32(encoded, cursor)?;
    if length == u32::MAX {
        Ok(None)
    } else {
        Ok(Some(read_string_of_length(
            encoded,
            cursor,
            length as usize,
        )?))
    }
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("project sync payload field is too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_string(encoded: &[u8], cursor: &mut usize) -> Result<String> {
    let length = read_u32(encoded, cursor)? as usize;
    read_string_of_length(encoded, cursor, length)
}

fn read_string_of_length(encoded: &[u8], cursor: &mut usize, length: usize) -> Result<String> {
    String::from_utf8(take(encoded, cursor, length)?.to_vec())
        .map_err(|_| anyhow!("incoming project sync payload contains invalid UTF-8"))
}

fn read_u32(encoded: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        take(encoded, cursor, 4)?
            .try_into()
            .expect("four-byte length"),
    ))
}

fn take<'a>(encoded: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    if length > MAX_FIELD_BYTES {
        bail!("incoming project sync payload field is too large");
    }
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| anyhow!("incoming project sync payload length overflow"))?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("incoming project sync payload is truncated"))?;
    *cursor = end;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(bytes.iter().map(|byte| byte ^ 0xA5).collect())
    }

    fn open(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            bytes.iter().map(|byte| byte ^ 0xA5).collect(),
        ))
    }

    fn insert_project(
        store: &Store,
        id: &str,
        name: &str,
        remote: &str,
        updated_at: &str,
        local_path: Option<&str>,
    ) {
        store
            .insert_synced_project(&SyncProject {
                id,
                name,
                git_remote: Some(remote),
                branch: Some("main"),
                package_manager: Some("cargo"),
                profile_ref: Some("local"),
                updated_at,
            })
            .unwrap();
        if let Some(path) = local_path {
            store.set_project_local_path(id, path).unwrap();
        }
    }

    #[test]
    fn payload_never_contains_the_senders_local_path_or_separator() {
        let store = Store::open_in_memory().unwrap();
        let sender_path = r"C:\Users\sender\Desktop\portable";
        store
            .upsert_project(
                "portable",
                Some("origin"),
                Some("main"),
                Some("cargo"),
                None,
                sender_path,
            )
            .unwrap();
        let record = build_records_with(&store, seal).unwrap().remove(0);
        let plaintext = open(&record.ciphertext).unwrap();
        assert!(!plaintext
            .windows(sender_path.len())
            .any(|part| part == sender_path.as_bytes()));
        assert!(!plaintext.contains(&b'\\'));
        let decoded = decode_payload(&plaintext).unwrap();
        assert_eq!(decoded.name, "portable");
    }

    #[test]
    fn receiving_a_newer_project_never_overwrites_local_path() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        insert_project(
            &sender,
            "01SHARED",
            "demo",
            "new-remote",
            "2026-07-15T11:00:00.000000000Z",
            None,
        );
        insert_project(
            &receiver,
            "01SHARED",
            "demo",
            "old-remote",
            "2026-07-15T10:00:00.000000000Z",
            Some(r"D:\work\demo"),
        );

        let records = build_records_with(&sender, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open).unwrap();
        assert_eq!((summary.received, summary.conflicted), (1, 1));
        let project = receiver.find_project_by_id("01SHARED").unwrap().unwrap();
        assert_eq!(project.git_remote.as_deref(), Some("new-remote"));
        assert_eq!(project.local_path.as_deref(), Some(r"D:\work\demo"));
    }

    #[test]
    fn a_new_id_with_an_existing_name_is_a_loud_conflict() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        insert_project(
            &sender,
            "01SENDER",
            "demo",
            "sender",
            "2026-07-15T11:00:00.000000000Z",
            None,
        );
        insert_project(
            &receiver,
            "01LOCAL",
            "demo",
            "local",
            "2026-07-15T10:00:00.000000000Z",
            None,
        );

        let records = build_records_with(&sender, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (0, 1, 1)
        );
        assert!(summary.warnings[0].contains("CONFLICT"));
        assert!(receiver.find_project_by_id("01SENDER").unwrap().is_none());
    }

    #[test]
    fn lww_uses_instants_across_both_timestamp_formats() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        insert_project(
            &sender,
            "01SHARED",
            "demo",
            "stale",
            "999999999.000000000Z",
            None,
        );
        insert_project(
            &receiver,
            "01SHARED",
            "demo",
            "current",
            "2026-07-14T19:27:16.358278100Z",
            None,
        );

        let records = build_records_with(&sender, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (0, 1, 1)
        );
        assert_eq!(
            receiver
                .find_project_by_id("01SHARED")
                .unwrap()
                .unwrap()
                .git_remote
                .as_deref(),
            Some("current")
        );
    }

    #[test]
    fn an_unorderable_conflict_keeps_local_and_reports() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        insert_project(&sender, "01SHARED", "demo", "incoming", "garbage", None);
        insert_project(
            &receiver,
            "01SHARED",
            "demo",
            "local",
            "2026-07-15T10:00:00.000000000Z",
            None,
        );

        let records = build_records_with(&sender, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (0, 1, 1)
        );
        assert!(summary.warnings[0].contains("cannot be ordered"));
        assert_eq!(
            receiver
                .find_project_by_id("01SHARED")
                .unwrap()
                .unwrap()
                .git_remote
                .as_deref(),
            Some("local")
        );
    }
}
