//! Device keys in the OS credential store (ADR 0004).
//!
//! Each key is one credential: 32 raw bytes under the service
//! `shardx-launcher`, with its `credential_ref` as the user. Entries are
//! created with `persistence = Local`, because the Windows store's default,
//! `Enterprise`, roams with the profile and would put one device identity on
//! two machines. A key counts as stored only once it reads back unchanged.
//!
//! On platforms without a backend, every call fails with
//! `credential.unavailable` and callers keep the key where it was.

use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

/// The service every launcher credential is filed under.
pub const SERVICE: &str = "shardx-launcher";

fn unavailable() -> anyhow::Error {
    anyhow!(crate::errcode::code("credential.unavailable"))
}

/// Sets the platform store as the default, once per process.
#[cfg(all(windows, not(test)))]
fn ensure_store() -> Result<()> {
    static STORE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let ready = *STORE.get_or_init(|| match windows_native_keyring_store::Store::new() {
        Ok(store) => {
            keyring_core::set_default_store(store);
            true
        }
        Err(_) => false,
    });
    if ready {
        Ok(())
    } else {
        Err(unavailable())
    }
}

#[cfg(all(not(windows), not(test)))]
fn ensure_store() -> Result<()> {
    Err(unavailable())
}

/// Tests run against the in-memory mock store, on every platform.
#[cfg(test)]
fn ensure_store() -> Result<()> {
    static STORE: std::sync::Once = std::sync::Once::new();
    STORE.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
    Ok(())
}

fn entry(credential_ref: &str) -> Result<keyring_core::Entry> {
    ensure_store()?;
    // The mock store takes no modifiers; the real one must never roam.
    #[cfg(not(test))]
    let entry = keyring_core::Entry::new_with_modifiers(
        SERVICE,
        credential_ref,
        &std::collections::HashMap::from([("persistence", "Local")]),
    );
    #[cfg(test)]
    let entry = keyring_core::Entry::new(SERVICE, credential_ref);
    entry.map_err(|_| unavailable())
}

/// Stores `key` under `credential_ref` and reads it back. Only an exact
/// read-back counts: on any failure the caller keeps its own copy.
pub fn store(credential_ref: &str, key: &[u8; 32]) -> Result<()> {
    let entry = entry(credential_ref)?;
    entry.set_secret(key).map_err(|_| unavailable())?;
    let back = Zeroizing::new(entry.get_secret().map_err(|_| unavailable())?);
    if back.as_slice() != key {
        return Err(anyhow!(crate::errcode::code("credential.readBackMismatch")));
    }
    Ok(())
}

/// The key under `credential_ref`. A missing credential is an error: a
/// reference is only ever kept for a key that was stored.
pub fn load(credential_ref: &str) -> Result<Zeroizing<[u8; 32]>> {
    let secret = Zeroizing::new(match entry(credential_ref)?.get_secret() {
        Ok(secret) => secret,
        Err(keyring_core::Error::NoEntry) => {
            return Err(anyhow!(crate::errcode::code("credential.missing")))
        }
        Err(_) => return Err(unavailable()),
    });
    let mut key = Zeroizing::new([0u8; 32]);
    if secret.len() != key.len() {
        return Err(anyhow!(crate::errcode::code("credential.missing")));
    }
    key.copy_from_slice(&secret);
    Ok(key)
}

/// Deletes the credential under `credential_ref`; one that is already gone
/// counts as deleted.
pub fn forget(credential_ref: &str) -> Result<()> {
    match entry(credential_ref)?.delete_credential() {
        Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
        Err(_) => Err(unavailable()),
    }
}

/// Makes the next store call on `credential_ref` fail, as a locked or
/// unreachable store would.
#[cfg(test)]
pub(crate) fn fail_next_call(credential_ref: &str) {
    let entry = entry(credential_ref).unwrap();
    let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();
    mock.set_error(keyring_core::Error::Invalid(
        "store".into(),
        "locked".into(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips_and_is_forgotten() {
        let key = [0xd8; 32];
        store("test-round-trip", &key).unwrap();
        assert_eq!(*load("test-round-trip").unwrap(), key);
        store("test-round-trip", &[7; 32]).unwrap();
        assert_eq!(*load("test-round-trip").unwrap(), [7; 32]);
        forget("test-round-trip").unwrap();
        let err = load("test-round-trip").unwrap_err();
        assert!(err.to_string().contains("credential.missing"), "{err}");
        forget("test-round-trip").unwrap();
    }

    #[test]
    fn references_are_separate_credentials() {
        store("test-a", &[1; 32]).unwrap();
        store("test-b", &[2; 32]).unwrap();
        assert_eq!(*load("test-a").unwrap(), [1; 32]);
        assert_eq!(*load("test-b").unwrap(), [2; 32]);
    }

    #[test]
    fn a_failed_write_or_read_back_is_reported() {
        let entry = entry("test-fail").unwrap();
        let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(keyring_core::Error::Invalid(
            "store".into(),
            "locked".into(),
        ));
        assert!(store("test-fail", &[3; 32]).is_err());
        entry.set_secret(&[9; 31]).unwrap();
        let err = load("test-fail").unwrap_err();
        assert!(
            err.to_string().contains("credential.missing"),
            "a short secret is no key: {err}"
        );
    }
}
