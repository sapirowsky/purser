//! Purser sync: peer-to-peer replication between the owner's own devices.
//!
//! Seam 3: sync moves *opaque encrypted records* behind a transport trait. It deliberately
//! does not know the word "secret" — a record is just `(id, version, ciphertext)`. v1's
//! transport is p2p QUIC (iroh); a relay or blob backend (R2/S3) swaps in later behind the
//! same trait with no caller changes. That swap point is also the monetization seam.

/// The only thing sync ever moves: an opaque, encrypted, versioned record.
#[derive(Debug, Clone)]
pub struct Record {
    pub id: String,
    pub version: u64,
    pub ciphertext: Vec<u8>,
}

/// Transport abstraction (seam 3). v1 impl = p2p QUIC; later = relay / blob backend.
pub trait Transport {
    /// Replicate a record to peers.
    fn send(&self, record: &Record);
    /// Drain records received from peers since the last cursor.
    fn recv(&self) -> Vec<Record>;
}

// TODO: iroh-backed Transport impl; device pairing (PAKE/Noise seeded by a one-time code);
// last-writer-wins-per-version reconciliation with full history retained.
