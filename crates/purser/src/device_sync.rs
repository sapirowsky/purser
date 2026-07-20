//! Device mesh (v1.1). Devices gossip their device list as a fourth synced record type, so
//! any two paired devices learn about every other paired device — no machine is a hub.
//!
//! Reconciliation is by PUBLIC KEY, never by the ULID row id: each device minted its own row
//! for a shared peer at pair time, so the ids differ across senders while the key is the one
//! true identity. `is_self` is never gossiped — it is a device's private opinion of itself,
//! exactly like a project's `local_path`.

use anyhow::{anyhow, bail, Context, Result};
use purser_store::{Device, Store};
use purser_sync::Record;
use zeroize::{Zeroize, Zeroizing};

const RECORD_PREFIX: &str = "device:";
const PAYLOAD_MAGIC: &[u8; 8] = b"PURDEV1\0";
const MAX_FIELD_BYTES: usize = 64 * 1024;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SyncSummary {
    pub sent: usize,
    pub received: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

impl SyncSummary {
    pub fn render(&self) -> String {
        format!(
            "Devices: {} records sent, {} received, {} skipped.",
            self.sent, self.received, self.skipped
        )
    }
}

struct DevicePayload {
    id: String,
    label: String,
    public_key: Vec<u8>,
    paired_at: String,
    revoked: bool,
}

impl Drop for DevicePayload {
    fn drop(&mut self) {
        self.id.zeroize();
        self.label.zeroize();
        self.paired_at.zeroize();
        self.public_key.zeroize();
    }
}

pub(crate) fn is_device_record(record: &Record) -> bool {
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
    // Gossip every device this machine knows — including its own self row, so peers learn
    // about THIS device too. The payload carries no is_self flag; the receiver decides.
    let devices = store.list_devices()?;
    let mut records = Vec::with_capacity(devices.len());
    for device in devices {
        let mut payload = encode_payload(&device)?;
        let ciphertext =
            encrypt(&payload).context("could not encrypt a device replication payload")?;
        payload.zeroize();
        records.push(Record {
            id: format!("{RECORD_PREFIX}{}", device.id),
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
    let self_key: Option<Vec<u8>> = store
        .list_devices()?
        .into_iter()
        .find(|device| device.is_self)
        .map(|device| device.public_key);

    let mut summary = SyncSummary::default();
    for record in records {
        let envelope_id = record
            .id
            .strip_prefix(RECORD_PREFIX)
            .ok_or_else(|| anyhow!("device sync record has the wrong namespace"))?;
        if record.version != 1 {
            bail!("device sync record has an unsupported version");
        }
        let mut plaintext = decrypt(&record.ciphertext)
            .context("could not decrypt a device replication payload")?;
        let payload = decode_payload(&plaintext)?;
        plaintext.zeroize();
        if payload.id != envelope_id {
            bail!("encrypted device payload identity does not match its record envelope");
        }

        // A device sees its own key echoed back from every peer; it must never turn that into
        // a peer row or overwrite its own self row.
        if self_key.as_deref() == Some(payload.public_key.as_slice()) {
            summary.skipped += 1;
            continue;
        }

        store.apply_gossiped_device(
            &payload.label,
            &payload.public_key,
            &payload.paired_at,
            payload.revoked,
        )?;
        summary.received += 1;
    }
    Ok(summary)
}

fn encode_payload(device: &Device) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    output.extend_from_slice(PAYLOAD_MAGIC);
    write_bytes(&mut output, device.id.as_bytes())?;
    write_bytes(&mut output, device.label.as_bytes())?;
    write_bytes(&mut output, &device.public_key)?;
    write_bytes(&mut output, device.paired_at.as_bytes())?;
    output.push(u8::from(device.revoked));
    Ok(output)
}

fn decode_payload(encoded: &[u8]) -> Result<DevicePayload> {
    let mut cursor = 0;
    if take(encoded, &mut cursor, PAYLOAD_MAGIC.len())? != PAYLOAD_MAGIC {
        bail!("incoming device sync payload has an invalid format");
    }
    let id = read_string(encoded, &mut cursor)?;
    let label = read_string(encoded, &mut cursor)?;
    let public_key = read_length_prefixed(encoded, &mut cursor)?.to_vec();
    let paired_at = read_string(encoded, &mut cursor)?;
    let revoked = match take(encoded, &mut cursor, 1)?[0] {
        0 => false,
        1 => true,
        _ => bail!("incoming device sync payload has an invalid revoked flag"),
    };
    if cursor != encoded.len() {
        bail!("incoming device sync payload has trailing bytes");
    }
    Ok(DevicePayload {
        id,
        label,
        public_key,
        paired_at,
        revoked,
    })
}

fn write_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("device sync payload field is too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_string(encoded: &[u8], cursor: &mut usize) -> Result<String> {
    let bytes = read_length_prefixed(encoded, cursor)?;
    String::from_utf8(bytes.to_vec())
        .map_err(|_| anyhow!("incoming device sync payload contains invalid UTF-8"))
}

fn read_length_prefixed<'a>(encoded: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let length = read_u32(encoded, cursor)? as usize;
    take(encoded, cursor, length)
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
        bail!("incoming device sync payload field is too large");
    }
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| anyhow!("incoming device sync payload length overflow"))?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("incoming device sync payload is truncated"))?;
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

    /// A three-device mesh: A is paired with B and with C, but B and C have never met. When
    /// A gossips its device list to C, C must learn B exists (by B's public key).
    #[test]
    fn gossip_teaches_a_device_about_a_peer_it_never_paired_with() {
        let a = Store::open_in_memory().unwrap();
        a.upsert_self_device("A", &[0xA1; 32]).unwrap();
        a.upsert_paired_device("B", &[0xB2; 32]).unwrap();
        a.upsert_paired_device("C", &[0xC3; 32]).unwrap();

        let c = Store::open_in_memory().unwrap();
        c.upsert_self_device("C", &[0xC3; 32]).unwrap();
        c.upsert_paired_device("A", &[0xA1; 32]).unwrap();

        let records = build_records_with(&a, seal).unwrap();
        let summary = apply_records_with(&c, &records, open).unwrap();

        // C ignored the record describing itself, and learned B.
        assert!(summary.skipped >= 1, "C must ignore its own gossiped row");
        let learned = c.find_device_by_public_key(&[0xB2; 32]).unwrap().unwrap();
        assert_eq!(learned.label, "B");
        assert!(!learned.is_self);
        assert!(!learned.revoked);
    }

    #[test]
    fn a_revoked_tombstone_propagates_and_is_sticky() {
        let a = Store::open_in_memory().unwrap();
        a.upsert_self_device("A", &[0xA1; 32]).unwrap();
        a.upsert_paired_device("B", &[0xB2; 32]).unwrap();
        assert_eq!(a.revoke_peer_by_label("B").unwrap(), 1);

        let c = Store::open_in_memory().unwrap();
        c.upsert_self_device("C", &[0xC3; 32]).unwrap();
        c.upsert_paired_device("B", &[0xB2; 32]).unwrap(); // C still thinks B is fine

        apply_records_with(&c, &build_records_with(&a, seal).unwrap(), open).unwrap();
        assert!(
            c.find_device_by_public_key(&[0xB2; 32])
                .unwrap()
                .unwrap()
                .revoked,
            "the revocation must spread to C"
        );

        // A later gossip that does NOT mark B revoked must not un-revoke it.
        let d = Store::open_in_memory().unwrap();
        d.upsert_self_device("D", &[0xD4; 32]).unwrap();
        d.upsert_paired_device("B", &[0xB2; 32]).unwrap(); // D sees B as fine
        apply_records_with(&c, &build_records_with(&d, seal).unwrap(), open).unwrap();
        assert!(
            c.find_device_by_public_key(&[0xB2; 32])
                .unwrap()
                .unwrap()
                .revoked,
            "revoked is sticky; a stale non-revoked gossip must not undo it"
        );
    }
}
