//! Purser sync: peer-to-peer replication between the owner's own devices.
//!
//! Seam 3 moves opaque encrypted records. It does not interpret their contents.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, SecretKey};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::future::Future;
use zeroize::{Zeroize, Zeroizing};

const ALPN: &[u8] = b"purser/transport/1";
const PAIRING_ALPN: &[u8] = b"purser/pair/1";
const PAIRING_KDF_INFO: &[u8] = b"purser/pair/1/v1";
const PAIRING_PROOF_LABEL: &[u8] = b"purser/pair/1/b";
const KEY_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 24;
const AEAD_TAG_BYTES: usize = 16;
const MAX_LABEL_BYTES: usize = 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

/// A decoded one-time pairing code. Its secret bytes are scrubbed on drop and it
/// deliberately has no `Debug` implementation.
pub struct PairingCode {
    peer: EndpointId,
    secret: Zeroizing<[u8; KEY_BYTES]>,
}

impl PairingCode {
    /// Generate a base64url code containing exactly `(node id || random secret)`.
    /// Base64url without padding is compact, copy/paste-safe, and unambiguous.
    pub fn generate(peer: EndpointId) -> (Zeroizing<String>, Self) {
        let mut secret = Zeroizing::new([0_u8; KEY_BYTES]);
        OsRng.fill_bytes(&mut secret[..]);
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES * 2]);
        bytes[..KEY_BYTES].copy_from_slice(peer.as_bytes());
        bytes[KEY_BYTES..].copy_from_slice(&secret[..]);
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(&bytes[..]));
        (encoded, Self { peer, secret })
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let mut bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| anyhow!("pairing code is not valid base64url"))?,
        );
        if bytes.len() != KEY_BYTES * 2 {
            bail!("pairing code has the wrong length");
        }
        let peer = EndpointId::from_bytes(
            bytes[..KEY_BYTES]
                .try_into()
                .expect("pairing node id has fixed length"),
        )
        .map_err(|_| anyhow!("pairing code contains an invalid node id"))?;
        let mut secret = Zeroizing::new([0_u8; KEY_BYTES]);
        secret.copy_from_slice(&bytes[KEY_BYTES..]);
        bytes.zeroize();
        Ok(Self { peer, secret })
    }

    pub fn peer(&self) -> EndpointId {
        self.peer
    }
}

/// Opaque 32-byte material transferred by pairing. This type intentionally has no
/// `Debug`; the sync crate neither interprets nor persists it.
pub struct PairingKeyMaterial(Zeroizing<[u8; KEY_BYTES]>);

impl PairingKeyMaterial {
    pub fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    pub fn from_zeroizing(bytes: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self(bytes)
    }
}

pub struct PairedPeer {
    pub id: EndpointId,
    pub label: String,
}

pub struct ReceivedPairing {
    pub peer: PairedPeer,
    pub key_material: PairingKeyMaterial,
}

/// The only thing sync ever moves: an opaque, encrypted, versioned record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    pub version: u64,
    pub ciphertext: Vec<u8>,
}

/// Transport abstraction for opaque records (seam 3).
pub trait Transport {
    fn send<'a>(&'a self, record: &'a Record) -> impl Future<Output = Result<()>> + Send + 'a;
    fn recv(&self) -> impl Future<Output = Result<Record>> + Send + '_;
}

/// A connected iroh QUIC transport. Each record occupies one unidirectional stream.
#[derive(Debug, Clone)]
pub struct IrohTransport {
    connection: iroh::endpoint::Connection,
}

impl IrohTransport {
    pub async fn bind(secret_key: SecretKey) -> Result<Endpoint> {
        Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .context("could not bind the iroh endpoint")
    }

    pub async fn connect(endpoint: &Endpoint, peer: impl Into<EndpointAddr>) -> Result<Self> {
        let connection = endpoint
            .connect(peer, ALPN)
            .await
            .context("could not connect to the iroh peer")?;
        Ok(Self { connection })
    }

    pub async fn accept(endpoint: &Endpoint) -> Result<(Self, EndpointId)> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("the iroh endpoint closed while listening"))?;
        let connection = incoming
            .await
            .context("could not complete the incoming iroh handshake")?;
        let peer = connection.remote_id();
        Ok((Self { connection }, peer))
    }

    pub fn peer_id(&self) -> EndpointId {
        self.connection.remote_id()
    }
}

impl Transport for IrohTransport {
    async fn send<'a>(&'a self, record: &'a Record) -> Result<()> {
        let encoded = encode(record)?;
        let mut stream = self
            .connection
            .open_uni()
            .await
            .context("could not open an iroh send stream")?;
        stream
            .write_all(&encoded)
            .await
            .context("could not write an iroh record")?;
        stream.finish().context("could not finish an iroh record")?;
        // Wait for the peer to consume the stream before returning, since the caller may
        // drop the connection the moment it does — which would close the record away
        // before it is delivered. The outcome is deliberately ignored: a peer that hangs
        // up as soon as it has what it needs is ending the exchange normally, not failing
        // it, and a peer that never reads is detected by that peer, not by us. Confirming
        // a record is durably stored is the replication protocol's job (3c), not the
        // transport's.
        let _ = stream.stopped().await;
        Ok(())
    }

    async fn recv(&self) -> Result<Record> {
        let mut stream = self
            .connection
            .accept_uni()
            .await
            .context("could not accept an iroh receive stream")?;
        let encoded = stream
            .read_to_end(MAX_RECORD_BYTES)
            .await
            .context("could not read an iroh record")?;
        decode(&encoded)
    }
}

/// Bind an endpoint that negotiates only the pairing protocol. It cannot accept the
/// unauthenticated 3a hello ALPN, and `IrohTransport::bind` cannot accept pairing.
pub async fn bind_pairing(secret_key: SecretKey) -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![PAIRING_ALPN.to_vec()])
        .bind()
        .await
        .context("could not bind the iroh pairing endpoint")
}

pub async fn accept_pairing(endpoint: &Endpoint) -> Result<iroh::endpoint::Connection> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow!("the iroh pairing endpoint closed while listening"))?;
    incoming
        .await
        .context("could not complete the incoming iroh pairing handshake")
}

pub async fn connect_pairing(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
) -> Result<iroh::endpoint::Connection> {
    endpoint
        .connect(peer, PAIRING_ALPN)
        .await
        .context("could not connect to the iroh pairing peer")
}

/// Authorize one peer and transfer opaque key material. The provider is deliberately
/// invoked only after `proof_b` has passed constant-time verification. On every earlier
/// error path, no key material exists in this function and therefore cannot be written.
pub async fn serve_pairing<F>(
    connection: iroh::endpoint::Connection,
    local_id: EndpointId,
    code: &PairingCode,
    local_label: &str,
    provide_key_material: F,
) -> Result<PairedPeer>
where
    F: FnOnce() -> Result<PairingKeyMaterial>,
{
    let peer_id = connection.remote_id();
    if local_id != code.peer || local_id == peer_id {
        bail!("pairing connection identity mismatch");
    }
    validate_label(local_label)?;

    // A opens the stream because A speaks first. Sending Na makes the stream visible to
    // B; opening on B and then waiting for A would deadlock under QUIC stream semantics.
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("could not open pairing handshake stream")?;
    let mut nonce_a = Zeroizing::new([0_u8; KEY_BYTES]);
    OsRng.fill_bytes(&mut nonce_a[..]);
    send.write_all(&nonce_a[..])
        .await
        .context("could not send pairing challenge")?;
    write_label(&mut send, local_label).await?;

    let mut nonce_b = Zeroizing::new([0_u8; KEY_BYTES]);
    recv.read_exact(&mut nonce_b[..])
        .await
        .context("could not read pairing response nonce")?;
    let mut proof = Zeroizing::new([0_u8; KEY_BYTES]);
    recv.read_exact(&mut proof[..])
        .await
        .context("could not read pairing proof")?;
    let peer_label = read_label(&mut recv).await?;

    let mut derived_key = derive_pairing_key(&code.secret)?;
    let mut verifier = <Hmac<Sha256> as Mac>::new_from_slice(&derived_key[..])
        .expect("HMAC accepts a 32-byte key");
    verifier.update(PAIRING_PROOF_LABEL);
    verifier.update(&nonce_a[..]);
    verifier.update(&nonce_b[..]);
    verifier.update(local_id.as_bytes());
    verifier.update(peer_id.as_bytes());
    if verifier.verify_slice(&proof[..]).is_err() {
        // In particular, do not send an error frame: after a bad proof this side writes
        // no more bytes at all, making accidental key disclosure structurally difficult.
        let _ = send.reset(0_u8.into());
        bail!("pairing proof was refused");
    }

    // SECURITY BOUNDARY: this is the first point at which key material may be loaded.
    let key_material = provide_key_material()?;
    let aad = pairing_aad(local_id, peer_id, &nonce_a, &nonce_b);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived_key[..]));
    let mut aead_nonce = Zeroizing::new([0_u8; AEAD_NONCE_BYTES]);
    OsRng.fill_bytes(&mut aead_nonce[..]);
    let mut encrypted = Zeroizing::new(
        cipher
            .encrypt(
                XNonce::from_slice(&aead_nonce[..]),
                Payload {
                    msg: key_material.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("could not encrypt pairing payload"))?,
    );
    // Successful AEAD decryption also proves to B that A knew the derived key, so a
    // separate proof_a would add complexity without adding authentication.
    send.write_all(&aead_nonce[..])
        .await
        .context("could not send pairing payload nonce")?;
    send.write_all(&encrypted[..])
        .await
        .context("could not send pairing payload")?;
    send.finish().context("could not finish pairing payload")?;
    let _ = send.stopped().await;
    encrypted.zeroize();
    derived_key.zeroize();
    Ok(PairedPeer {
        id: peer_id,
        label: peer_label,
    })
}

pub async fn request_pairing(
    connection: iroh::endpoint::Connection,
    local_id: EndpointId,
    code: &PairingCode,
    local_label: &str,
) -> Result<ReceivedPairing> {
    let peer_id = connection.remote_id();
    if peer_id != code.peer || local_id == peer_id {
        bail!("pairing connection identity mismatch");
    }
    validate_label(local_label)?;

    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .context("pairing peer did not open its handshake stream")?;
    let mut nonce_a = Zeroizing::new([0_u8; KEY_BYTES]);
    recv.read_exact(&mut nonce_a[..])
        .await
        .context("pairing peer did not provide a challenge")?;
    let peer_label = read_label(&mut recv).await?;
    let mut nonce_b = Zeroizing::new([0_u8; KEY_BYTES]);
    OsRng.fill_bytes(&mut nonce_b[..]);
    let mut derived_key = derive_pairing_key(&code.secret)?;
    let mut prover = <Hmac<Sha256> as Mac>::new_from_slice(&derived_key[..])
        .expect("HMAC accepts a 32-byte key");
    prover.update(PAIRING_PROOF_LABEL);
    prover.update(&nonce_a[..]);
    prover.update(&nonce_b[..]);
    prover.update(peer_id.as_bytes());
    prover.update(local_id.as_bytes());
    let mut tag = prover.finalize().into_bytes();
    let mut proof = Zeroizing::new([0_u8; KEY_BYTES]);
    proof.copy_from_slice(&tag);
    tag.as_mut_slice().zeroize();
    send.write_all(&nonce_b[..])
        .await
        .context("could not send pairing response nonce")?;
    send.write_all(&proof[..])
        .await
        .context("could not send pairing proof")?;
    write_label(&mut send, local_label).await?;
    send.finish().context("could not finish pairing proof")?;
    proof.zeroize();

    let mut aead_nonce = Zeroizing::new([0_u8; AEAD_NONCE_BYTES]);
    recv.read_exact(&mut aead_nonce[..])
        .await
        .context("pairing peer refused authorization")?;
    let mut encrypted = Zeroizing::new([0_u8; KEY_BYTES + AEAD_TAG_BYTES]);
    recv.read_exact(&mut encrypted[..])
        .await
        .context("pairing peer did not provide key material")?;
    let aad = pairing_aad(peer_id, local_id, &nonce_a, &nonce_b);
    let decrypted = XChaCha20Poly1305::new(Key::from_slice(&derived_key[..]))
        .decrypt(
            XNonce::from_slice(&aead_nonce[..]),
            Payload {
                msg: &encrypted[..],
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("pairing payload authentication failed"))?;
    let mut decrypted = Zeroizing::new(decrypted);
    let bytes: [u8; KEY_BYTES] = decrypted
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pairing payload has the wrong length"))?;
    decrypted.zeroize();
    encrypted.zeroize();
    derived_key.zeroize();
    Ok(ReceivedPairing {
        peer: PairedPeer {
            id: peer_id,
            label: peer_label,
        },
        key_material: PairingKeyMaterial::new(bytes),
    })
}

fn derive_pairing_key(secret: &[u8; KEY_BYTES]) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    Hkdf::<Sha256>::new(None, secret)
        .expand(PAIRING_KDF_INFO, &mut key[..])
        .map_err(|_| anyhow!("could not derive the pairing key"))?;
    Ok(key)
}

fn pairing_aad(
    id_a: EndpointId,
    id_b: EndpointId,
    nonce_a: &[u8; KEY_BYTES],
    nonce_b: &[u8; KEY_BYTES],
) -> Zeroizing<Vec<u8>> {
    let mut aad = Zeroizing::new(Vec::with_capacity(KEY_BYTES * 4));
    aad.extend_from_slice(id_a.as_bytes());
    aad.extend_from_slice(id_b.as_bytes());
    aad.extend_from_slice(nonce_a);
    aad.extend_from_slice(nonce_b);
    aad
}

fn validate_label(label: &str) -> Result<()> {
    if label.len() > MAX_LABEL_BYTES {
        bail!("device label is too long");
    }
    Ok(())
}

async fn write_label(send: &mut iroh::endpoint::SendStream, label: &str) -> Result<()> {
    validate_label(label)?;
    let length = u16::try_from(label.len()).expect("validated label fits in u16");
    send.write_all(&length.to_be_bytes())
        .await
        .context("could not send device label length")?;
    send.write_all(label.as_bytes())
        .await
        .context("could not send device label")?;
    Ok(())
}

async fn read_label(recv: &mut iroh::endpoint::RecvStream) -> Result<String> {
    let mut length = [0_u8; 2];
    recv.read_exact(&mut length)
        .await
        .context("could not read device label length")?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_LABEL_BYTES {
        bail!("peer device label is too long");
    }
    let mut bytes = vec![0_u8; length];
    recv.read_exact(&mut bytes)
        .await
        .context("could not read device label")?;
    String::from_utf8(bytes).context("peer device label is not UTF-8")
}

fn encode(record: &Record) -> Result<Vec<u8>> {
    let id = record.id.as_bytes();
    let id_len = u32::try_from(id.len()).context("record id is too large")?;
    let ciphertext_len = u32::try_from(record.ciphertext.len()).context("record is too large")?;
    let total = 4_usize
        .checked_add(id.len())
        .and_then(|value| value.checked_add(8 + 4))
        .and_then(|value| value.checked_add(record.ciphertext.len()))
        .ok_or_else(|| anyhow!("record is too large"))?;
    if total > MAX_RECORD_BYTES {
        bail!("record exceeds the transport limit");
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&id_len.to_be_bytes());
    encoded.extend_from_slice(id);
    encoded.extend_from_slice(&record.version.to_be_bytes());
    encoded.extend_from_slice(&ciphertext_len.to_be_bytes());
    encoded.extend_from_slice(&record.ciphertext);
    Ok(encoded)
}

fn decode(encoded: &[u8]) -> Result<Record> {
    let mut cursor = 0;
    let id_len = take_u32(encoded, &mut cursor)? as usize;
    let id = take(encoded, &mut cursor, id_len)?;
    let version = take_u64(encoded, &mut cursor)?;
    let ciphertext_len = take_u32(encoded, &mut cursor)? as usize;
    let ciphertext = take(encoded, &mut cursor, ciphertext_len)?.to_vec();
    if cursor != encoded.len() {
        bail!("record frame has trailing bytes");
    }
    Ok(Record {
        id: String::from_utf8(id.to_vec()).context("record id is not UTF-8")?,
        version,
        ciphertext,
    })
}

fn take<'a>(encoded: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| anyhow!("record frame length overflow"))?;
    let value = encoded
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("record frame is truncated"))?;
    *cursor = end;
    Ok(value)
}

fn take_u32(encoded: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        take(encoded, cursor, 4)?.try_into().expect("four bytes"),
    ))
}

fn take_u64(encoded: &[u8], cursor: &mut usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        take(encoded, cursor, 8)?.try_into().expect("eight bytes"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_encoding_round_trips_and_rejects_trailing_data() {
        let record = Record {
            id: "opaque-id".into(),
            version: 42,
            ciphertext: vec![0, 1, 2, 255],
        };
        let encoded = encode(&record).unwrap();
        assert_eq!(decode(&encoded).unwrap(), record);

        let mut malformed = encoded;
        malformed.push(0);
        assert!(decode(&malformed).is_err());
    }

    #[test]
    fn pairing_code_is_unpadded_base64url_and_carries_the_node_id() {
        let id = SecretKey::generate().public();
        let (encoded, code) = PairingCode::generate(id);
        assert_eq!(encoded.len(), 86);
        assert!(encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
        assert_eq!(code.peer(), id);
        assert_eq!(PairingCode::decode(&encoded).unwrap().peer(), id);
    }
}
