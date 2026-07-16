//! XChaCha20-Poly1305 encryption backed by one OS-keyring vault key.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "purser";
const VAULT_KEY_ACCOUNT: &str = "vault-key";
const DEVICE_KEY_ACCOUNT: &str = "device-key";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("could not access the operating-system keyring for Purser: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("Purser's stored vault key is invalid")]
    InvalidStoredKey,
    #[error("this device already has a vault key; pairing will not overwrite it")]
    VaultKeyAlreadyExists,
    #[error("this device does not have a vault key to transfer")]
    VaultKeyMissing,
    #[error("encrypted secret data is malformed")]
    MalformedCiphertext,
    #[error("secret encryption or authentication failed")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Encrypt bytes with the persistent OS-keyring key. The result is nonce || ciphertext.
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut key = load_or_create_key(VAULT_KEY_ACCOUNT)?;
    let result = encrypt_with_key(&key, plaintext);
    key.zeroize();
    result
}

/// Authenticate and decrypt bytes into a buffer that scrubs itself on drop.
pub fn decrypt(encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut key = load_or_create_key(VAULT_KEY_ACCOUNT)?;
    let result = decrypt_with_key(&key, encrypted).map(Zeroizing::new);
    key.zeroize();
    result
}

/// This device's networking identity: a key that is independent of the vault key and,
/// unlike it, never leaves the machine. Pairing hands a peer the vault key; handing over
/// device identity too would let a peer impersonate this device.
pub fn device_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    load_or_create_key(DEVICE_KEY_ACCOUNT)
}

/// Report whether this scoped device already owns a vault key without creating one.
pub fn vault_key_exists() -> Result<bool> {
    Ok(load_existing_key(VAULT_KEY_ACCOUNT)?.is_some())
}

/// Load the vault key for an authorized pairing response. Unlike encryption, this never
/// creates a key: an enrolling device must actually hold the key it claims to transfer.
pub fn export_vault_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    load_existing_key(VAULT_KEY_ACCOUNT)?.ok_or(VaultError::VaultKeyMissing)
}

/// Install received vault key bytes only into an empty scoped account. This function
/// must never use keyring's overwrite behavior for an account observed to exist.
pub fn install_vault_key_if_absent(key: &[u8; KEY_LEN]) -> Result<()> {
    let account = scoped_account(VAULT_KEY_ACCOUNT, purser_core::device_scope().as_deref());
    let entry = keyring::Entry::new(SERVICE, &account)?;
    install_if_absent(
        || match entry.get_secret() {
            Ok(mut stored) => {
                stored.zeroize();
                Ok(true)
            }
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(VaultError::Keyring(error)),
        },
        || entry.set_secret(key).map_err(VaultError::Keyring),
    )
}

/// Remove this scoped device's vault key and device key from the OS keyring. An absent key
/// is not an error — the goal is that nothing of ours remains afterward.
///
/// IRREVERSIBLE: once the vault key is gone, this device's encrypted secrets can never be
/// decrypted again. Callers must confirm intent before calling.
pub fn delete_all_keys() -> Result<()> {
    delete_scoped_key(VAULT_KEY_ACCOUNT)?;
    delete_scoped_key(DEVICE_KEY_ACCOUNT)?;
    Ok(())
}

fn delete_scoped_key(account: &str) -> Result<()> {
    let account = scoped_account(account, purser_core::device_scope().as_deref());
    let entry = keyring::Entry::new(SERVICE, &account)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(VaultError::Keyring(error)),
    }
}

/// Qualify a keyring account with the device scope, so a virtual device never shares
/// the real device's keys.
fn scoped_account(account: &str, scope: Option<&str>) -> String {
    match scope {
        Some(scope) => format!("{account}:{scope}"),
        None => account.to_owned(),
    }
}

fn load_or_create_key(account: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    // TODO: Add an encrypted-key-file fallback for systems (notably some WSL setups)
    // without a working Secret Service. Keyring errors intentionally remain errors today.
    let account = scoped_account(account, purser_core::device_scope().as_deref());
    let entry = keyring::Entry::new(SERVICE, &account)?;
    match entry.get_secret() {
        Ok(mut stored) => {
            if stored.len() != KEY_LEN {
                stored.zeroize();
                return Err(VaultError::InvalidStoredKey);
            }
            let mut key = [0_u8; KEY_LEN];
            key.copy_from_slice(&stored);
            stored.zeroize();
            Ok(Zeroizing::new(key))
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = Zeroizing::new([0_u8; KEY_LEN]);
            OsRng.fill_bytes(&mut key[..]);
            if let Err(error) = entry.set_secret(&key[..]) {
                key.zeroize();
                return Err(VaultError::Keyring(error));
            }
            Ok(key)
        }
        Err(error) => Err(VaultError::Keyring(error)),
    }
}

fn load_existing_key(account: &str) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
    let account = scoped_account(account, purser_core::device_scope().as_deref());
    let entry = keyring::Entry::new(SERVICE, &account)?;
    match entry.get_secret() {
        Ok(mut stored) => {
            if stored.len() != KEY_LEN {
                stored.zeroize();
                return Err(VaultError::InvalidStoredKey);
            }
            let mut key = [0_u8; KEY_LEN];
            key.copy_from_slice(&stored);
            stored.zeroize();
            Ok(Some(Zeroizing::new(key)))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(VaultError::Keyring(error)),
    }
}

fn install_if_absent(
    exists: impl FnOnce() -> Result<bool>,
    install: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if exists()? {
        return Err(VaultError::VaultKeyAlreadyExists);
    }
    install()
}

/// Encrypt with caller-supplied vault material without accessing the OS keyring.
///
/// Normal callers should use [`encrypt`]. This entry point exists so protocol integration
/// tests can exercise the exact production AEAD while remaining isolated from real keys.
#[doc(hidden)]
pub fn encrypt_with_key(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
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

/// Decrypt with caller-supplied vault material without accessing the OS keyring.
///
/// Normal callers should use [`decrypt`].
#[doc(hidden)]
pub fn decrypt_with_key(key: &[u8; KEY_LEN], encrypted: &[u8]) -> Result<Vec<u8>> {
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
    fn a_device_scope_separates_every_key_from_the_real_devices() {
        assert_eq!(scoped_account(VAULT_KEY_ACCOUNT, None), "vault-key");
        assert_eq!(scoped_account(DEVICE_KEY_ACCOUNT, None), "device-key");

        // The vault key must be scoped too, not just the device key: two virtual devices
        // sharing one vault key would make pairing a no-op and prove nothing.
        assert_eq!(
            scoped_account(VAULT_KEY_ACCOUNT, Some("mac-sim")),
            "vault-key:mac-sim"
        );
        assert_eq!(
            scoped_account(DEVICE_KEY_ACCOUNT, Some("mac-sim")),
            "device-key:mac-sim"
        );
        assert_ne!(
            scoped_account(DEVICE_KEY_ACCOUNT, Some("mac-sim")),
            scoped_account(DEVICE_KEY_ACCOUNT, Some("other")),
        );
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

    #[test]
    fn installing_a_vault_key_never_calls_overwriting_setter() {
        let setter_called = std::cell::Cell::new(false);
        let result = install_if_absent(
            || Ok(true),
            || {
                setter_called.set(true);
                Ok(())
            },
        );

        assert!(matches!(result, Err(VaultError::VaultKeyAlreadyExists)));
        assert!(!setter_called.get(), "existing vault key was overwritten");
    }
}
