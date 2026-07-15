use anyhow::{anyhow, bail, Context, Result};
use purser_store::Store;
use purser_sync::Record;
use zeroize::{Zeroize, Zeroizing};

const PAYLOAD_MAGIC: &[u8; 8] = b"PURSYNC1";
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
            "Sync complete: {} secret records sent, {} received, {} skipped, {} conflicted.",
            self.sent, self.received, self.skipped, self.conflicted
        )
    }
}

struct SecretPayload {
    secret_id: String,
    name: String,
    profile: String,
    group: Option<String>,
    value: Zeroizing<Vec<u8>>,
    version: u64,
    created_at: String,
}

impl Drop for SecretPayload {
    fn drop(&mut self) {
        self.secret_id.zeroize();
        self.name.zeroize();
        self.profile.zeroize();
        if let Some(group) = &mut self.group {
            group.zeroize();
        }
        self.created_at.zeroize();
    }
}

pub(crate) fn build_records(store: &Store) -> Result<Vec<Record>> {
    build_records_with(
        store,
        |bytes| Ok(purser_vault::decrypt(bytes)?),
        |bytes| Ok(purser_vault::encrypt(bytes)?),
    )
}

pub(crate) fn apply_records(store: &Store, records: &[Record]) -> Result<SyncSummary> {
    apply_records_with(
        store,
        records,
        |bytes| Ok(purser_vault::decrypt(bytes)?),
        |bytes| Ok(purser_vault::encrypt(bytes)?),
    )
}

pub(crate) fn build_records_with<D, E>(
    store: &Store,
    mut decrypt_at_rest: D,
    mut encrypt_payload: E,
) -> Result<Vec<Record>>
where
    D: FnMut(&[u8]) -> Result<Zeroizing<Vec<u8>>>,
    E: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let rows = store.all_secret_versions_for_sync()?;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let value = decrypt_at_rest(&row.ciphertext)
            .context("could not decrypt an at-rest value for sync")?;
        let version = u64::try_from(row.version).context("stored secret version is invalid")?;
        let mut payload = encode_payload(
            &row.secret_id,
            &row.name,
            &row.profile,
            row.group.as_deref(),
            &value[..],
            version,
            &row.created_at,
        )?;
        let ciphertext = encrypt_payload(&payload[..])
            .context("could not encrypt a secret replication payload")?;
        payload.zeroize();
        records.push(Record {
            id: row.secret_id,
            version,
            ciphertext,
        });
    }
    Ok(records)
}

pub(crate) fn apply_records_with<D, E>(
    store: &Store,
    records: &[Record],
    mut decrypt_payload: D,
    mut encrypt_at_rest: E,
) -> Result<SyncSummary>
where
    D: FnMut(&[u8]) -> Result<Zeroizing<Vec<u8>>>,
    E: FnMut(&[u8]) -> Result<Vec<u8>>,
{
    let mut summary = SyncSummary::default();
    for record in records {
        let mut plaintext = decrypt_payload(&record.ciphertext)
            .context("could not decrypt a secret replication payload")?;
        let payload = decode_payload(&plaintext[..])?;
        plaintext.zeroize();
        if payload.secret_id != record.id || payload.version != record.version {
            bail!("encrypted sync payload identity does not match its record envelope");
        }
        let version = i64::try_from(payload.version).context("incoming version is too large")?;

        match store.find_secret_by_id(&payload.secret_id)? {
            Some(existing)
                if existing.name != payload.name || existing.profile != payload.profile =>
            {
                summary.skipped += 1;
                summary.conflicted += 1;
                summary.warnings.push(format!(
                    "CONFLICT: secret id {} has different local metadata; record skipped",
                    payload.secret_id
                ));
                continue;
            }
            Some(_) => {}
            None => {
                if let Some(existing) =
                    store.find_secret_by_name_profile(&payload.name, &payload.profile)?
                {
                    if existing.id != payload.secret_id {
                        summary.skipped += 1;
                        summary.conflicted += 1;
                        summary.warnings.push(format!(
                            "CONFLICT: incoming secret {} in profile {} has a different id; record skipped",
                            payload.name, payload.profile
                        ));
                        continue;
                    }
                }
            }
        }

        let existing_version = store.find_secret_version(&payload.secret_id, version)?;
        if let Some(existing_version) = existing_version {
            store.mark_synced_secret_configured(&payload.secret_id, payload.group.as_deref())?;
            let local_value = decrypt_payload(&existing_version.ciphertext)
                .context("could not decrypt a local value during conflict comparison")?;
            if local_value[..] == payload.value[..] {
                summary.skipped += 1;
                continue;
            }

            summary.conflicted += 1;
            let Some(order) =
                compare_write_times(&payload.created_at, &existing_version.created_at)
            else {
                // Neither value is destroyed: the local one stays, the incoming one is
                // still in the sender's history, and the owner is told to pick.
                summary.skipped += 1;
                summary.warnings.push(format!(
                    "CONFLICT: concurrent edits to secret {} version {}, but their write times \
                     cannot be ordered; kept the local value — resolve this one by hand",
                    payload.name, payload.version
                ));
                continue;
            };
            summary.warnings.push(format!(
                "CONFLICT: concurrent edits to secret {} version {}; last writer wins",
                payload.name, payload.version
            ));
            if order.is_gt() {
                let ciphertext = encrypt_at_rest(&payload.value[..])
                    .context("could not encrypt a received value for local storage")?;
                store.replace_synced_secret_version(
                    &payload.secret_id,
                    version,
                    &ciphertext,
                    &payload.created_at,
                )?;
                summary.received += 1;
            } else {
                summary.skipped += 1;
            }
            continue;
        }

        let ciphertext = encrypt_at_rest(&payload.value[..])
            .context("could not encrypt a received value for local storage")?;
        if store.find_secret_by_id(&payload.secret_id)?.is_none() {
            store.insert_synced_secret(
                &payload.secret_id,
                &payload.name,
                &payload.profile,
                payload.group.as_deref(),
                &payload.created_at,
            )?;
        }
        store.insert_synced_secret_version(
            &payload.secret_id,
            version,
            &ciphertext,
            &payload.created_at,
        )?;
        store.mark_synced_secret_configured(&payload.secret_id, payload.group.as_deref())?;
        summary.received += 1;
    }
    Ok(summary)
}

/// Order two `created_at` values by the instant they were written, or `None` if either is
/// unrecognized. Never compare these as strings: the database holds more than one
/// timestamp format, and string order contradicts real time across them.
///
/// This orders by each writer's own wall clock, so it is only as good as the clocks
/// agreeing. Two devices whose clocks differ by more than the gap between two edits can
/// pick the wrong winner. The losing value is never destroyed — it stays in the sender's
/// version history — but that is a real limitation, not a theoretical one.
fn compare_write_times(incoming: &str, local: &str) -> Option<std::cmp::Ordering> {
    let incoming = purser_store::unix_nanos_from_timestamp(incoming)?;
    let local = purser_store::unix_nanos_from_timestamp(local)?;
    Some(incoming.cmp(&local))
}

fn encode_payload(
    secret_id: &str,
    name: &str,
    profile: &str,
    group: Option<&str>,
    value: &[u8],
    version: u64,
    created_at: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    output.extend_from_slice(PAYLOAD_MAGIC);
    write_bytes(&mut output, secret_id.as_bytes())?;
    write_bytes(&mut output, name.as_bytes())?;
    write_bytes(&mut output, profile.as_bytes())?;
    match group {
        Some(group) => write_bytes(&mut output, group.as_bytes())?,
        None => output.extend_from_slice(&u32::MAX.to_be_bytes()),
    }
    write_bytes(&mut output, value)?;
    output.extend_from_slice(&version.to_be_bytes());
    write_bytes(&mut output, created_at.as_bytes())?;
    Ok(output)
}

fn decode_payload(encoded: &[u8]) -> Result<SecretPayload> {
    let mut cursor = 0;
    if take(encoded, &mut cursor, PAYLOAD_MAGIC.len())? != PAYLOAD_MAGIC {
        bail!("incoming sync payload has an invalid format");
    }
    let secret_id = read_string(encoded, &mut cursor)?;
    let name = read_string(encoded, &mut cursor)?;
    let profile = read_string(encoded, &mut cursor)?;
    let group_length = read_u32(encoded, &mut cursor)?;
    let group = if group_length == u32::MAX {
        None
    } else {
        Some(read_string_of_length(
            encoded,
            &mut cursor,
            group_length as usize,
        )?)
    };
    let value_length = read_u32(encoded, &mut cursor)? as usize;
    let value = Zeroizing::new(take(encoded, &mut cursor, value_length)?.to_vec());
    let version = u64::from_be_bytes(
        take(encoded, &mut cursor, 8)?
            .try_into()
            .expect("eight-byte version"),
    );
    let created_at = read_string(encoded, &mut cursor)?;
    if cursor != encoded.len() {
        bail!("incoming sync payload has trailing bytes");
    }
    Ok(SecretPayload {
        secret_id,
        name,
        profile,
        group,
        value,
        version,
        created_at,
    })
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("sync payload field is too large")?;
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
        .map_err(|_| anyhow!("incoming sync payload contains invalid UTF-8"))
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
        bail!("incoming sync payload field is too large");
    }
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| anyhow!("incoming sync payload length overflow"))?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("incoming sync payload is truncated"))?;
    *cursor = end;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut output = b"sealed:".to_vec();
        output.push(0);
        output.extend(bytes.iter().map(|byte| byte ^ 0xA5));
        Ok(output)
    }

    fn seal_with_nonce(bytes: &[u8], nonce: u8) -> Vec<u8> {
        let mut output = b"sealed:".to_vec();
        output.push(nonce);
        output.extend(bytes.iter().map(|byte| byte ^ 0xA5));
        output
    }

    fn open(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let body = bytes
            .strip_prefix(b"sealed:")
            .ok_or_else(|| anyhow!("authentication failed"))?;
        let body = body
            .get(1..)
            .ok_or_else(|| anyhow!("authentication failed"))?;
        Ok(Zeroizing::new(
            body.iter().map(|byte| byte ^ 0xA5).collect(),
        ))
    }

    fn insert_version(
        store: &Store,
        id: &str,
        name: &str,
        profile: &str,
        version: i64,
        value: &[u8],
        created_at: &str,
    ) {
        if store.find_secret_by_id(id).unwrap().is_none() {
            store
                .insert_synced_secret(id, name, profile, None, created_at)
                .unwrap();
        }
        store
            .insert_synced_secret_version(id, version, &seal(value).unwrap(), created_at)
            .unwrap();
    }

    #[test]
    fn name_collision_is_a_loud_skip_and_summary_never_contains_the_value() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        let secret_value = b"VALUE-MUST-NOT-APPEAR-IN-OUTPUT";
        insert_version(
            &sender,
            "01SENDER",
            "TOKEN",
            "test",
            1,
            secret_value,
            "2026-07-15T10:00:00.000000000Z",
        );
        insert_version(
            &receiver,
            "01RECEIVER",
            "TOKEN",
            "test",
            1,
            b"local",
            "2026-07-15T09:00:00.000000000Z",
        );
        let records = build_records_with(&sender, open, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open, seal).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (0, 1, 1)
        );
        let output = format!("{}\n{}", summary.render(), summary.warnings.join("\n"));
        assert!(output.contains("CONFLICT"));
        assert!(!output.contains(std::str::from_utf8(secret_value).unwrap()));
    }

    #[test]
    fn versions_are_unioned_and_same_version_uses_created_at_lww() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        for (version, value, timestamp) in [
            (1, b"history".as_slice(), "2026-07-15T08:00:00.000000000Z"),
            (
                2,
                b"remote-wins".as_slice(),
                "2026-07-15T11:00:00.000000000Z",
            ),
        ] {
            insert_version(
                &sender, "01SHARED", "TOKEN", "test", version, value, timestamp,
            );
        }
        insert_version(
            &receiver,
            "01SHARED",
            "TOKEN",
            "test",
            2,
            b"local-loses",
            "2026-07-15T10:00:00.000000000Z",
        );

        let records = build_records_with(&sender, open, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open, seal).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (2, 0, 1)
        );
        let versions = receiver.all_secret_versions_for_sync().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(
            open(&versions[1].ciphertext).unwrap()[..],
            b"remote-wins"[..]
        );
        assert!(summary.warnings[0].contains("last writer wins"));
    }

    #[test]
    fn lww_across_the_two_stored_timestamp_formats_follows_real_time() {
        // A stale incoming value whose timestamp string sorts ABOVE the newer local one.
        // Comparing these as strings hands the conflict to the stale value; comparing the
        // instants they name keeps the current one.
        let stale_epoch_form = "999999999.000000000Z"; // 2001-09-09
        let current_civil_form = "2026-07-14T19:27:16.358278100Z";
        assert!(
            stale_epoch_form > current_civil_form,
            "string order would pick the stale value"
        );

        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        insert_version(
            &sender,
            "01SHARED",
            "TOKEN",
            "test",
            1,
            b"stale-must-lose",
            stale_epoch_form,
        );
        insert_version(
            &receiver,
            "01SHARED",
            "TOKEN",
            "test",
            1,
            b"current-must-win",
            current_civil_form,
        );

        let records = build_records_with(&sender, open, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open, seal).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (0, 1, 1)
        );
        let versions = receiver.all_secret_versions_for_sync().unwrap();
        assert_eq!(
            open(&versions[0].ciphertext).unwrap()[..],
            b"current-must-win"[..]
        );
    }

    #[test]
    fn an_unorderable_conflict_keeps_the_local_value_instead_of_guessing() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        insert_version(
            &sender,
            "01SHARED",
            "TOKEN",
            "test",
            1,
            b"incoming",
            "garbage",
        );
        insert_version(
            &receiver,
            "01SHARED",
            "TOKEN",
            "test",
            1,
            b"local-kept",
            "2026-07-14T19:27:16.358278100Z",
        );

        let records = build_records_with(&sender, open, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open, seal).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (0, 1, 1)
        );
        let versions = receiver.all_secret_versions_for_sync().unwrap();
        assert_eq!(
            open(&versions[0].ciphertext).unwrap()[..],
            b"local-kept"[..]
        );
        assert!(summary.warnings[0].contains("cannot be ordered"));
    }

    #[test]
    fn different_nonce_bytes_for_the_same_value_are_not_a_conflict() {
        let sender = Store::open_in_memory().unwrap();
        let receiver = Store::open_in_memory().unwrap();
        insert_version(
            &sender,
            "01SHARED",
            "TOKEN",
            "test",
            1,
            b"same-value",
            "2026-07-15T10:00:00.000000000Z",
        );
        receiver
            .insert_synced_secret(
                "01SHARED",
                "TOKEN",
                "test",
                None,
                "2026-07-15T10:00:00.000000000Z",
            )
            .unwrap();
        receiver
            .insert_synced_secret_version(
                "01SHARED",
                1,
                &seal_with_nonce(b"same-value", 99),
                "2026-07-15T10:00:00.000000000Z",
            )
            .unwrap();

        let records = build_records_with(&sender, open, seal).unwrap();
        let summary = apply_records_with(&receiver, &records, open, seal).unwrap();
        assert_eq!(
            (summary.received, summary.skipped, summary.conflicted),
            (0, 1, 0)
        );
        assert!(summary.warnings.is_empty());
    }
}
