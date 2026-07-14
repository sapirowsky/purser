//! XChaCha20-Poly1305 encryption backed by one OS-keyring vault key.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "purser";
const ACCOUNT: &str = "vault-key";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("could not access the operating-system keyring for Purser: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("Purser's stored vault key is invalid")]
    InvalidStoredKey,
    #[error("encrypted secret data is malformed")]
    MalformedCiphertext,
    #[error("secret encryption or authentication failed")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Encrypt bytes with the persistent OS-keyring key. The result is nonce || ciphertext.
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut key = load_or_create_key()?;
    let result = encrypt_with_key(&key, plaintext);
    key.zeroize();
    result
}

/// Authenticate and decrypt bytes into a buffer that scrubs itself on drop.
pub fn decrypt(encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = load_or_create_key()?;
    let result = decrypt_with_key(&key, encrypted).map(Zeroizing::new);
    key.zeroize();
    result
}

fn load_or_create_key() -> Result<[u8; KEY_LEN]> {
    // TODO: Add an encrypted-key-file fallback for systems (notably some WSL setups)
    // without a working Secret Service. Keyring errors intentionally remain errors today.
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    match entry.get_secret() {
        Ok(mut stored) => {
            if stored.len() != KEY_LEN {
                stored.zeroize();
                return Err(VaultError::InvalidStoredKey);
            }
            let mut key = [0_u8; KEY_LEN];
            key.copy_from_slice(&stored);
            stored.zeroize();
            Ok(key)
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = [0_u8; KEY_LEN];
            OsRng.fill_bytes(&mut key);
            if let Err(error) = entry.set_secret(&key) {
                key.zeroize();
                return Err(VaultError::Keyring(error));
            }
            Ok(key)
        }
        Err(error) => Err(VaultError::Keyring(error)),
    }
}

fn encrypt_with_key(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| VaultError::Crypto)?;
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    nonce_bytes.zeroize();
    Ok(output)
}

fn decrypt_with_key(key: &[u8; KEY_LEN], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_LEN {
        return Err(VaultError::MalformedCiphertext);
    }
    let (nonce, ciphertext) = encrypted.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_round_trips_and_is_not_plaintext() {
        let key = [7_u8; KEY_LEN];
        let plaintext = b"vault-roundtrip-secret";
        let encrypted = encrypt_with_key(&key, plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert_eq!(decrypt_with_key(&key, &encrypted).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_and_corruption_fail_authentication() {
        let key = [11_u8; KEY_LEN];
        let encrypted = encrypt_with_key(&key, b"authenticated secret").unwrap();
        assert!(decrypt_with_key(&[12_u8; KEY_LEN], &encrypted).is_err());

        let mut corrupted = encrypted;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(decrypt_with_key(&key, &corrupted).is_err());
        assert!(decrypt_with_key(&key, b"short").is_err());
    }
}
